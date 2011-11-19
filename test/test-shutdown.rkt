#lang racket/base



(require "../mzssl.rkt"
         rackunit
         (planet okcomps/racket-test))


(define (test-ssl-server clear-i clear-o #:close-original? (close-original #t))
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define-values (i o) (ports->ssl-ports clear-i clear-o #:context server-context #:mode 'accept #:close-original? close-original))
  
  (let loop ([next (read i)])
    (printf "server read ~v~n" next)
    (cond [(or (equal? next eof)
               (equal? next "shutdown"))
           (close-input-port i)
           (close-output-port o)]
          
          [else
           (write next o)
           (flush-output o)
           (loop (read i))])))


(ssl-enable-verbose-logging #t)

(define-unit-test connection-test
    
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)]
                [(server-thd) (thread (λ () (test-ssl-server i1 o2)))]
                [(client-i client-o) (ports->ssl-ports i2 o1 #:context client-context #:mode 'connect #:close-original? #t)])
    
    (printf "writing hi~n")
    (write "hi" client-o)
    (close-output-port client-o)
    
    
    (let ([in (read client-i)])
      (printf "read ~v on client input~n" in)
      (check-equal? in "hi"))
    
    
    
    (close-input-port client-i)
    
    (thread-wait server-thd)))
      



;simple send through and read back test
;but leave the original ports open
(define-unit-test shutdown-not-close-original
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)]
                [(server-thd) (thread (λ () (test-ssl-server i1 o2 #:close-original? #f)))]
                [(client-i client-o) (ports->ssl-ports i2 o1 #:context client-context #:mode 'connect #:close-original? #f)])
    
    (write "shutdown" client-o)
    
      ;port should be now closed after the shutdown occurs
    (check-equal? (read client-i) eof)
      
    (close-input-port client-i)
    (close-output-port client-o)
    
    (thread-wait server-thd)
      
    (check-false (port-closed? i1))
    (check-false (port-closed? i2))
      
    (check-false (port-closed? o1))
    (check-false (port-closed? o2))
      
    ;there should be no garbage information on the underlying ports
    (check-false (byte-ready? i1))
    (check-false (byte-ready? i2))))


#|
connects to the server, requests the server to shutdown and then
continues to write to the server. The write operations shold eventually
throw an exception
|#
(define-unit-test shutdown-write-should-fail
    (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)]
                [(server-thd) (thread (λ () (test-ssl-server i1 o2)))]
                [(client-i client-o) (ports->ssl-ports i2 o1 #:context client-context #:mode 'connect #:close-original? #t)])
    
    (write "shutdown" client-o)
    
    (thread-wait server-thd)
    
    (check-exn exn:fail:network? (λ ()
                                   (let loop ()
                                     (write #"a" client-o)
                                     (loop))))))
  



(map (λ (t)
         (t))
       (tests))


;situations to check
;connection is shutdown, read block forever?
;connection is shutdown, a write should eventually cause errors




#|

;determines if shutdown notify works correctly
;between 2 connections
;that is an ssl session can be run over a port
;if the ssl session ends, the port is left open
;and another ssl session can begin
;the ssl ports will be themselves closed,
;but the underlying ports will remain open and able to work normally
(define-unit-test shutdown-notify
  (test-timeout 5000)
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)])
    (thread (λ ()
              (let-values ([(ssl-i1 ssl-o1) (ports->ssl-ports i1 o2 #:context server-context #:mode 'accept #:close-original? #f)])
                (printf "Server read: ~v~n" (read ssl-i1))
                (close-input-port ssl-i1)
                (write "OK" ssl-o1)
                (close-output-port ssl-o1))))
    
    (let-values ([(ssl-i2 ssl-o2) (ports->ssl-ports i2 o1 #:context client-context #:close-original? #f)])
      (write "hi" ssl-o2)
      (close-output-port ssl-o2)
      ;read until the port closes, at which point we know the underlying ssl connection has been shutdown
      
      (printf "got back ~v~n" (read ssl-i2))
      (close-input-port ssl-i2))))|#

#|
(define-values (i1 o1) (make-pipe))
(define-values (i2 o2) (make-pipe))
(make-ssl-test-ports i1 o2 i2 o1 #:close-original? #f)|#