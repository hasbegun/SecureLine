package com.innoc.secureline.signaling;


public class RateLimitExceededException extends Throwable {
  public RateLimitExceededException(String s) {
    super(s);
  }
}
