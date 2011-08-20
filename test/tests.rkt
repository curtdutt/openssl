#lang racket/base


(define (stress-rapid-connection-test-series)
  ;in loop
  ;open
  ;send
  ;close
  #f)


(define (stress-rapid-connection-test-parallel)
  ;many connections at once
  ;in loop
  ;open
  ;send
  ;close
  #f)

(define (stress-long-running-connection-test)
  ;open a single connection
  ;pipe through lots and lots and lots of data
  ;but with very big packets
  #f)

(define (stress-long-running-connection-test)
  ;open a single connection
  ;pipe through lots and lots of miniture tests
  ;little packets
  #f)

(define (performance-connections-per-second
  