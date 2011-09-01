#lang racket

(require "mzssl.rkt")

(define main-cust (make-custodian))

;(define wrapper-custodian (make-custodian))
;(define client-context (ssl-make-client-context))

;(ssl-load-certificate-chain! client-context "test.pem")
;(ssl-load-private-key! client-context "test.pem")


;(current-custodian wrapper-custodian)

(define (test)
  (define server-context (ssl-make-server-context))
  
  (ssl-load-private-key! server-context "test.pem")
  (ssl-load-certificate-chain! server-context "test.pem")
  (ssl-load-verify-root-certificates! server-context "test.pem")
  
  ;(ssl-set-verify! server-context #t)
  
  (define listener (ssl-listen 8443 4 #f #f server-context))
  
  
  (define (servlet listener)
    (thread (λ ()
              (let-values ([(in out) (ssl-accept listener)])
                (let ([n (read in)])
                  (printf "server accepted ~a~n" n)
                  (write n out))
                (close-input-port in)
                (close-output-port out)))))
    
  
  (define server-thread 
    (thread (λ ()
              (printf "serving!~n")
              (let loop ()
                (let ([next-thread (servlet listener)])
                  (sync next-thread)
                  (loop))))))
              
  #t)
  
  
(parameterize ([current-custodian main-cust])
  (test))

;(current-custodian main-cust)

;(custodian-shutdown-all wrapper-custodian)
#|
(define (send msg)
  (let-values ([(in out) (ssl-connect "localhost" 8443 client-context)])
    (write msg out)
    (printf "~v~n" (read in))
    (close-output-port out)
    (close-input-port in)))
  |#   
            
                                
;(send "hello")


