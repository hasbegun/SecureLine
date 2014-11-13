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

package com.innoc.secureline.call;

import android.content.Context;
import android.util.Log;
import com.innoc.secureline.Release;
import com.innoc.secureline.audio.AudioException;
import com.innoc.secureline.audio.CallAudioManager;
import com.innoc.secureline.crypto.SecureRtpSocket;
import com.innoc.secureline.crypto.zrtp.MasterSecret;
import com.innoc.secureline.crypto.zrtp.ZRTPInitiatorSocket;
import com.innoc.secureline.network.RtpSocket;
import com.innoc.secureline.signaling.LoginFailedException;
import com.innoc.secureline.signaling.NetworkConnector;
import com.innoc.secureline.signaling.NoSuchUserException;
import com.innoc.secureline.signaling.OtpCounterProvider;
import com.innoc.secureline.signaling.ServerMessageException;
import com.innoc.secureline.signaling.SessionInitiationFailureException;
import com.innoc.secureline.signaling.SignalingException;
import com.innoc.secureline.signaling.SignalingSocket;
import com.innoc.secureline.ui.ApplicationPreferencesActivity;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;

/**
 * Call Manager for the coordination of outgoing calls.  It initiates
 * signaling, negotiates ZRTP, and kicks off the call audio manager.
 *
 * @author Moxie Marlinspike
 *
 */
public class InitiatingCallManager extends CallManager {

  private final String localNumber;
  private final String password;
  private final byte[] zid;
  private boolean loopbackMode;

  public InitiatingCallManager(Context context, CallStateListener callStateListener,
                               String localNumber, String password,
                               String remoteNumber, byte[] zid)
  {
    super(context, callStateListener, remoteNumber, "InitiatingCallManager Thread");
    this.localNumber    = localNumber;
    this.password       = password;
    this.zid            = zid;
    this.loopbackMode   = ApplicationPreferencesActivity.getLoopbackEnabled(context);
  }

  @Override
  public void run() {
    if( loopbackMode ) {
      runLoopback();
      return;
    }

    try {
      callStateListener.notifyCallConnecting();

      signalingSocket = new SignalingSocket(context, Release.RELAY_SERVER_HOST,
                                            Release.SERVER_PORT, localNumber, password,
                                            OtpCounterProvider.getInstance());

      sessionDescriptor = signalingSocket.initiateConnection(remoteNumber);

      int localPort = new NetworkConnector(sessionDescriptor.sessionId,
                                           sessionDescriptor.getFullServerName(),
                                           sessionDescriptor.relayPort).makeConnection();

      InetSocketAddress remoteAddress = new InetSocketAddress(sessionDescriptor.getFullServerName(),
                                                              sessionDescriptor.relayPort);

      secureSocket  = new SecureRtpSocket(new RtpSocket(localPort, remoteAddress));

      zrtpSocket    = new ZRTPInitiatorSocket(context, secureSocket, zid, remoteNumber);

      processSignals();

      callStateListener.notifyWaitingForResponder();

      super.run();
    } catch (NoSuchUserException nsue) {
      Log.w("InitiatingCallManager", nsue);
      callStateListener.notifyNoSuchUser();
    } catch (ServerMessageException ife) {
      Log.w("InitiatingCallManager", ife);
      callStateListener.notifyServerMessage(ife.getMessage());
    } catch (LoginFailedException lfe) {
      Log.w("InitiatingCallManager", lfe);
      callStateListener.notifyLoginFailed();
    } catch (SignalingException se) {
      Log.w("InitiatingCallManager", se);
      callStateListener.notifyServerFailure();
    } catch (SocketException e) {
      Log.w("InitiatingCallManager", e);
      callStateListener.notifyCallDisconnected();
    } catch( RuntimeException e ) {
      Log.e( "InitiatingCallManager", "Died with unhandled exception!");
      Log.w( "InitiatingCallManager", e );
      callStateListener.notifyClientFailure();
    } catch (SessionInitiationFailureException e) {
      Log.w("InitiatingCallManager", e);
      callStateListener.notifyServerFailure();
    }
  }

  @Override
  protected void runAudio(DatagramSocket socket, String remoteIp, int remotePort,
                          MasterSecret masterSecret, boolean muteEnabled)
      throws SocketException, AudioException
  {
    this.callAudioManager = new CallAudioManager(socket, remoteIp, remotePort,
                                                 masterSecret.getInitiatorSrtpKey(),
                                                 masterSecret.getInitiatorMacKey(),
                                                 masterSecret.getInitiatorSrtpSalt(),
                                                 masterSecret.getResponderSrtpKey(),
                                                 masterSecret.getResponderMacKey(),
                                                 masterSecret.getResponderSrtpSailt());
    this.callAudioManager.setMute(muteEnabled);
    this.callAudioManager.start();
  }

  //***************************
  // SOA's Loopback Code, for debugging.

  private void runLoopback() {
    try {
      super.doLoopback();
    } catch( Exception e ) {
      Log.e( "InitiatingCallManager", "Died with exception!");
      Log.w( "InitiatingCallManager", e );
      callStateListener.notifyClientFailure();
    }
  }

}
