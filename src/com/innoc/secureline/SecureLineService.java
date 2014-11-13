/*
 * Copyright (C) 2011 Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.innoc.secureline;

import android.app.Service;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.media.AudioManager;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.preference.PreferenceManager;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.innoc.secureline.audio.IncomingRinger;
import com.innoc.secureline.audio.OutgoingRinger;
import com.innoc.secureline.call.CallManager;
import com.innoc.secureline.call.CallStateListener;
import com.innoc.secureline.call.InitiatingCallManager;
import com.innoc.secureline.call.LockManager;
import com.innoc.secureline.call.ResponderCallManager;
import com.innoc.secureline.codec.CodecSetupException;
import com.innoc.secureline.contacts.PersonInfo;
import com.innoc.secureline.crypto.zrtp.SASInfo;
import com.innoc.secureline.gcm.GCMRegistrarHelper;
import com.innoc.secureline.pstn.CallStateView;
import com.innoc.secureline.pstn.IncomingPstnCallListener;
import com.innoc.secureline.signaling.OtpCounterProvider;
import com.innoc.secureline.signaling.SessionDescriptor;
import com.innoc.secureline.signaling.SignalingException;
import com.innoc.secureline.signaling.SignalingSocket;
import com.innoc.secureline.ui.NotificationBarManager;
import com.innoc.secureline.util.Base64;
import com.innoc.secureline.util.CallLogger;
import com.innoc.secureline.util.UncaughtExceptionHandlerManager;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

/**
 * The major entry point for all of the heavy lifting associated with
 * setting up, tearing down, or managing calls.  The service spins up
 * either from a broadcast listener that has detected an incoming call,
 * or from a UI element that wants to initiate an outgoing call.
 *
 * @author Moxie Marlinspike
 *
 */
public class SecureLineService extends Service implements CallStateListener, CallStateView {
  public static final String ACTION_INCOMING_CALL = "RedPhoneService.INCOMING_CALL";
  public static final String ACTION_OUTGOING_CALL = "RedPhoneService.OUTGOING_CALL";
  public static final String ACTION_ANSWER_CALL   = "RedPhoneService.ANSWER_CALL";
  public static final String ACTION_DENY_CALL     = "RedPhoneService.DENYU_CALL";
  public static final String ACTION_HANGUP_CALL   = "RedPhoneService.HANGUP";
  public static final String ACTION_SET_MUTE      = "RedPhoneService.SET_MUTE";
  public static final String ACTION_CONFIRM_SAS   = "RedPhoneService.CONFIRM_SAS";

  private static final String TAG = SecureLineService.class.getName();

  private final List<Message> bufferedEvents = new LinkedList<Message>();
  private final IBinder binder               = new SecureLineServiceBinder();
  private final Handler serviceHandler       = new Handler();

  private OutgoingRinger outgoingRinger;
  private IncomingRinger incomingRinger;

  private int state;
  private byte[] zid;
  private String localNumber;
  private String remoteNumber;
  private String password;
  private CallManager currentCallManager;
  private LockManager lockManager;
  private UncaughtExceptionHandlerManager uncaughtExceptionHandlerManager;

  private Handler handler;
  private CallLogger.CallRecord currentCallRecord;
  private IncomingPstnCallListener pstnCallListener;

  @Override
  public void onCreate() {
    super.onCreate();

    if (Release.DEBUG) Log.w(TAG, "Service onCreate() called...");

    initializeResources();
    initializeApplicationContext();
    initializeRingers();
    initializePstnCallListener();
    registerUncaughtExceptionHandler();
  }

  @Override
  public void onStart(Intent intent, int startId) {
    if (Release.DEBUG) Log.w(TAG, "Service onStart() called...");
    if (intent == null) return;
    new Thread(new IntentRunnable(intent)).start();

    GCMRegistrarHelper.registerClient(this, false);
  }

  @Override
  public IBinder onBind(Intent intent) {
    return binder;
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    unregisterReceiver(pstnCallListener);
    NotificationBarManager.setCallEnded(this);
    uncaughtExceptionHandlerManager.unregister();
  }

  private synchronized void onIntentReceived(Intent intent) {
    Log.w(TAG, "Received Intent: " + intent.getAction());

    if      (intent.getAction().equals(ACTION_INCOMING_CALL) && isBusy()) handleBusyCall(intent);
    else if (intent.getAction().equals(ACTION_INCOMING_CALL))             handleIncomingCall(intent);
    else if (intent.getAction().equals(ACTION_OUTGOING_CALL) && isIdle()) handleOutgoingCall(intent);
    else if (intent.getAction().equals(ACTION_ANSWER_CALL))               handleAnswerCall(intent);
    else if (intent.getAction().equals(ACTION_DENY_CALL))                 handleDenyCall(intent);
    else if (intent.getAction().equals(ACTION_HANGUP_CALL))               handleHangupCall(intent);
    else if (intent.getAction().equals(ACTION_SET_MUTE))                  handleSetMute(intent);
    else if (intent.getAction().equals(ACTION_CONFIRM_SAS))               handleConfirmSas(intent);
  }

  ///// Initializers

  private void initializeRingers() {
    this.outgoingRinger = new OutgoingRinger(this);
    this.incomingRinger = new IncomingRinger(this);
  }

  private void initializePstnCallListener() {
    pstnCallListener = new IncomingPstnCallListener(this);
    registerReceiver(pstnCallListener, new IntentFilter("android.intent.action.PHONE_STATE"));
  }

  private void initializeApplicationContext() {
    ApplicationContext context = ApplicationContext.getInstance();
    context.setContext(this);
    context.setCallStateListener(this);
  }

  private void initializeResources() {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

    this.state            = SecureLine.STATE_IDLE;
    this.zid              = getZID();
    this.localNumber      = preferences.getString(Constants.NUMBER_PREFERENCE, "NO_SAVED_NUMBER!");
    this.password         = preferences.getString(Constants.PASSWORD_PREFERENCE, "NO_SAVED_PASSWORD!");

    this.lockManager      = new LockManager(this);
  }

  private void registerUncaughtExceptionHandler() {
    uncaughtExceptionHandlerManager = new UncaughtExceptionHandlerManager();
    uncaughtExceptionHandlerManager.registerHandler(new ProximityLockRelease(lockManager));
  }

  /// Intent Handlers

  private void handleIncomingCall(Intent intent) {
    SessionDescriptor session = (SessionDescriptor)intent.getParcelableExtra(Constants.SESSION);
    remoteNumber              = extractRemoteNumber(intent);
    state                     = SecureLine.STATE_RINGING;

    lockManager.updatePhoneState(LockManager.PhoneState.PROCESSING);
    this.currentCallManager = new ResponderCallManager(this, this, remoteNumber, localNumber,
                                                       password, session, zid);
    this.currentCallManager.start();
  }

  private void handleOutgoingCall(Intent intent) {
    remoteNumber = extractRemoteNumber(intent);

    if (remoteNumber == null || remoteNumber.length() == 0)
      return;

    sendMessage(SecureLine.HANDLE_OUTGOING_CALL, remoteNumber);

    state = SecureLine.STATE_DIALING;
    lockManager.updatePhoneState(LockManager.PhoneState.INTERACTIVE);
    this.currentCallManager = new InitiatingCallManager(this, this, localNumber, password,
                                                        remoteNumber, zid);
    this.currentCallManager.start();

    NotificationBarManager.setCallInProgress(this);

    currentCallRecord = CallLogger.logOutgoingCall(this, remoteNumber);
  }

  private void handleBusyCall(Intent intent) {
    SessionDescriptor session = (SessionDescriptor)intent.getParcelableExtra(Constants.SESSION);

    if (currentCallManager != null && session.equals(currentCallManager.getSessionDescriptor())) {
      Log.w("RedPhoneService", "Duplicate incoming call signal, ignoring...");
      return;
    }

    handleMissedCall(extractRemoteNumber(intent));

    try {
      SignalingSocket signalingSocket = new SignalingSocket(this, session.getFullServerName(),
                                                            Release.SERVER_PORT,
                                                            localNumber, password,
                                                            OtpCounterProvider.getInstance());

      signalingSocket.setBusy(session.sessionId);
      signalingSocket.close();
    } catch (SignalingException e) {
      Log.w("RedPhoneService", e);
    }
  }

  private void handleMissedCall(String remoteNumber) {
    CallLogger.logMissedCall(this, remoteNumber, System.currentTimeMillis());
    NotificationBarManager.notifyMissedCall(this, remoteNumber);
  }

  private void handleAnswerCall(Intent intent) {
    state = SecureLine.STATE_ANSWERING;
    incomingRinger.stop();
    currentCallRecord = CallLogger.logIncomingCall(this, remoteNumber);
    if (currentCallManager != null) {
      ((ResponderCallManager)this.currentCallManager).answer(true);
    }
  }

  private void handleDenyCall(Intent intent) {
    state = SecureLine.STATE_IDLE;
    incomingRinger.stop();
    CallLogger.logMissedCall(this, remoteNumber, System.currentTimeMillis());
    if(currentCallManager != null) {
      ((ResponderCallManager)this.currentCallManager).answer(false);
    }
    this.terminate();
  }

  private void handleHangupCall(Intent intent) {
    this.terminate();
  }

  private void handleSetMute(Intent intent) {
    if(currentCallManager != null) {
      currentCallManager.setMute(intent.getBooleanExtra(Constants.MUTE_VALUE, false));
    }
  }

  private void handleConfirmSas(Intent intent) {
    if (currentCallManager != null)
      currentCallManager.setSasVerified();
  }

  /// Helper Methods

  private boolean isBusy() {
    TelephonyManager telephonyManager = (TelephonyManager)getSystemService(TELEPHONY_SERVICE);
    return ((currentCallManager != null && state != SecureLine.STATE_IDLE) ||
             telephonyManager.getCallState() != TelephonyManager.CALL_STATE_IDLE);
  }

  private boolean isIdle() {
    return state == SecureLine.STATE_IDLE;
  }

  private void shutdownAudio() {
    AudioManager am = (AudioManager) getSystemService(AUDIO_SERVICE);
    am.setMode(AudioManager.MODE_NORMAL);
  }

  public int getState() {
    return state;
  }

  public SASInfo getCurrentCallSAS() {
    if (currentCallManager != null)
      return currentCallManager.getSasInfo();
    else
      return null;
  }

  public PersonInfo getRemotePersonInfo() {
    return PersonInfo.getInstance(this, remoteNumber);
  }

  private byte[] getZID() {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

    if (preferences.contains("ZID")) {
      try {
        return Base64.decode(preferences.getString("ZID", null));
      } catch (IOException e) {
        return setZID();
      }
    } else {
      return setZID();
    }
  }

  private byte[] setZID() {
    SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

    try {
      byte[] zid        = new byte[12];
      SecureRandom.getInstance("SHA1PRNG").nextBytes(zid);
      String encodedZid = Base64.encodeBytes(zid);

      preferences.edit().putString("ZID", encodedZid).commit();

      return zid;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private String extractRemoteNumber(Intent i) {
    String number =  i.getStringExtra(Constants.REMOTE_NUMBER);

    if (number == null)
      number = i.getData().getSchemeSpecificPart();

    if (number.endsWith("*")) return number.substring(0, number.length()-1);
    else                      return number;
  }

  private void startCallCardActivity() {
    Intent activityIntent = new Intent();
    activityIntent.setClass(this, SecureLine.class);
    activityIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    startActivity(activityIntent);
  }

  private synchronized void terminate() {
    Log.w("RedPhoneService", "termination stack", new Exception() );
    lockManager.updatePhoneState(LockManager.PhoneState.PROCESSING);
    NotificationBarManager.setCallEnded(this);

    incomingRinger.stop();
    outgoingRinger.stop();

    if (currentCallRecord != null) {
      currentCallRecord.finishCall();
      currentCallRecord = null;
    }

    if (currentCallManager != null) {
      currentCallManager.terminate();
      currentCallManager = null;
    }

    shutdownAudio();

    state = SecureLine.STATE_IDLE;
    lockManager.updatePhoneState(LockManager.PhoneState.IDLE);
    // XXX moxie@thoughtcrime.org -- Do we still need to stop the Service?
//    Log.d("RedPhoneService", "STOP SELF" );
//    this.stopSelf();
  }

  public void setCallStateHandler(Handler handler) {
    this.handler = handler;

    if (handler != null) {
      for (Message message : bufferedEvents) {
        handler.sendMessage(message);
      }

      bufferedEvents.clear();
    }
  }

  ///////// CallStateListener Implementation

  public void notifyCallStale() {
    Log.w("RedPhoneService", "Got a stale call, probably an old SMS...");
    handleMissedCall(remoteNumber);
    this.terminate();
  }

  public void notifyCallFresh() {
    Log.w("RedPhoneService", "Good call, time to ring and display call card...");
    sendMessage(SecureLine.HANDLE_INCOMING_CALL, remoteNumber);

    lockManager.updatePhoneState(LockManager.PhoneState.INTERACTIVE);

    startCallCardActivity();
    incomingRinger.start();

    NotificationBarManager.setCallInProgress(this);
  }

  public void notifyBusy() {
    Log.w("RedPhoneService", "Got busy signal from responder!");
    sendMessage(SecureLine.HANDLE_CALL_BUSY, null);
    outgoingRinger.playBusy();
    serviceHandler.postDelayed(new Runnable() {
      @Override
      public void run() {
        SecureLineService.this.terminate();
      }
    }, SecureLine.BUSY_SIGNAL_DELAY_FINISH);
  }

  public void notifyCallRinging() {
    outgoingRinger.playRing();
    sendMessage(SecureLine.HANDLE_CALL_RINGING, null);
  }

  public void notifyCallConnected(SASInfo sas) {
    outgoingRinger.playComplete();
    lockManager.updatePhoneState(LockManager.PhoneState.IN_CALL);
    state = SecureLine.STATE_CONNECTED;
    synchronized( this ) {
      sendMessage(SecureLine.HANDLE_CALL_CONNECTED, sas);
      try {
        wait();
      } catch (InterruptedException e) {
        throw new AssertionError( "Wait interrupted in RedPhoneService" );
      }
    }
  }
  public void notifyCallConnectionUIUpdateComplete() {
    synchronized( this ) {
      this.notify();
    }
  }
  public void notifyDebugInfo(String info) {
    sendMessage(SecureLine.HANDLE_DEBUG_INFO, info);
  }

  public void notifyConnectingtoInitiator() {
    sendMessage(SecureLine.HANDLE_CONNECTING_TO_INITIATOR, null);
  }

  public void notifyCallDisconnected() {
    if (state == SecureLine.STATE_RINGING)
      handleMissedCall(remoteNumber);

    sendMessage(SecureLine.HANDLE_CALL_DISCONNECTED, null);
    this.terminate();
  }

  public void notifyHandshakeFailed() {
    state = SecureLine.STATE_IDLE;
    outgoingRinger.playFailure();
    sendMessage(SecureLine.HANDLE_HANDSHAKE_FAILED, null);
    this.terminate();
  }

  public void notifyRecipientUnavailable() {
    state = SecureLine.STATE_IDLE;
    outgoingRinger.playFailure();
    sendMessage(SecureLine.HANDLE_RECIPIENT_UNAVAILABLE, null);
    this.terminate();
  }

  public void notifyPerformingHandshake() {
    outgoingRinger.playHandshake();
    sendMessage(SecureLine.HANDLE_PERFORMING_HANDSHAKE, null);
  }

  public void notifyServerFailure() {
    if (state == SecureLine.STATE_RINGING)
      handleMissedCall(remoteNumber);

    state = SecureLine.STATE_IDLE;
    outgoingRinger.playFailure();
    sendMessage(SecureLine.HANDLE_SERVER_FAILURE, null);
    this.terminate();
  }

  public void notifyClientFailure() {
    if (state == SecureLine.STATE_RINGING)
      handleMissedCall(remoteNumber);

    state = SecureLine.STATE_IDLE;
    outgoingRinger.playFailure();
    sendMessage(SecureLine.HANDLE_CLIENT_FAILURE, null);
    this.terminate();
  }

  public void notifyLoginFailed() {
    if (state == SecureLine.STATE_RINGING)
      handleMissedCall(remoteNumber);

    state = SecureLine.STATE_IDLE;
    outgoingRinger.playFailure();
    sendMessage(SecureLine.HANDLE_LOGIN_FAILED, null);
    this.terminate();
  }

  public void notifyNoSuchUser() {
    sendMessage(SecureLine.HANDLE_NO_SUCH_USER, remoteNumber);
    this.terminate();
  }

  public void notifyServerMessage(String message) {
    sendMessage(SecureLine.HANDLE_SERVER_MESSAGE, message);
    this.terminate();
  }

  public void notifyCodecInitFailed(CodecSetupException e) {
    sendMessage(SecureLine.HANDLE_CODEC_INIT_FAILED, e);
    this.terminate();
  }

  public void notifyClientError(String msg) {
    sendMessage(SecureLine.HANDLE_CLIENT_FAILURE,msg);
    this.terminate();
  }

  public void notifyClientError(int messageId) {
    notifyClientError(getString(messageId));
  }

  public void notifyCallConnecting() {
    outgoingRinger.playSonar();
  }

  public void notifyWaitingForResponder() {}

  private void sendMessage(int code, Object extra) {
    Message message = Message.obtain();
    message.what    = code;
    message.obj     = extra;

    if (handler != null) handler.sendMessage(message);
    else    			       bufferedEvents.add(message);
  }

  private class IntentRunnable implements Runnable {
    private final Intent intent;

    public IntentRunnable(Intent intent) {
      this.intent = intent;
    }

    public void run() {
      onIntentReceived(intent);
    }
  }

  public class SecureLineServiceBinder extends Binder {
    public SecureLineService getService() {
      return SecureLineService.this;
    }
  }

  @Override
  public boolean isInCall() {
    switch(state) {
      case SecureLine.STATE_IDLE:
        return false;
      case SecureLine.STATE_DIALING:
      case SecureLine.STATE_RINGING:
      case SecureLine.STATE_ANSWERING:
      case SecureLine.STATE_CONNECTED:
        return true;
      default:
        Log.e(TAG, "Unhandled call state: " + state);
        return false;
    }
  }

  private static class ProximityLockRelease implements Thread.UncaughtExceptionHandler {
    private final LockManager lockManager;

    private ProximityLockRelease(LockManager lockManager) {
      this.lockManager = lockManager;
    }

    @Override
    public void uncaughtException(Thread thread, Throwable throwable) {
      Log.d(TAG, "Uncaught exception - releasing proximity lock", throwable);
      lockManager.updatePhoneState(LockManager.PhoneState.IDLE);
    }
  }
}
