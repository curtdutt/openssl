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