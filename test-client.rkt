#lang racket

(require openssl)
;(require "mzssl.rkt")

(define client-context (ssl-make-client-context))
(ssl-load-certificate-chain! client-context "test.pem")
(ssl-load-private-key! client-context "test.pem")


(define (send msg)
  (let-values ([(in out) (ssl-connect "localhost" 8443 client-context)])
    (write msg out)
    (close-output-port out)
    (printf "wrote~n")
    (printf "~v~n" (read in))
    (close-input-port in)))

            
                                
(send "hello")
