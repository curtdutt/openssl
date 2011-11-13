#lang racket/base


(require (planet okcomps/racket-test)
         rackunit
         "../main.rkt")


(define (port-speed-test i o #:count-every (count-every #f))
  (let loop ([count 0])
    (let ([byte (read-byte i)])
      (write-byte byte o)
      (flush-output o))
    
    (when (and count-every (= (modulo count count-every) 0))
      (printf "wrote ~v bytes~n" count))
    
    (loop (add1 count))))
      
  
  
         

#| 
this test performs ssl throughput back and forth between two wrapped ports
it pumps pumps a single byte back and forth as fast as possible.

The purpose is to locate any memory leaks within a single ssl session.
|#


(define-stress-test wrap-ports-test
  (test-gc-interval 10000) 
  (test-limit-memory 200000)
  (test-timeout 300000)
  
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)])
    (thread (λ ()
              (let-values ([(ssl-i1 ssl-o1) (ports->ssl-ports i1 o2 #:context server-context #:mode 'accept)])
                (port-speed-test ssl-i1 ssl-o1))))
    
    (let-values ([(ssl-i2 ssl-o2) (ports->ssl-ports i2 o1 #:context client-context)])
      (write-byte 100 ssl-o2)
      (port-speed-test ssl-i2 ssl-o2 #:count-every 10000))))


#|
Creates connections similar to the wrap ports tests, however it writes 1 bytes to the server
reads 1 byte from the server and closes the connection. It then initiates a new connection rapidly
|#
(define-stress-test rapid-connection-test
  (test-gc-interval 5000) 
  (test-limit-memory 200000)
  (test-timeout 300000)
  
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let loop ([count 0])
   (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)])
     
    (thread (λ ()
              (let-values ([(ssl-i1 ssl-o1) (ports->ssl-ports i1 o2 #:context server-context #:mode 'accept  #:close-original? #t)])
                (write (read-byte ssl-i1) ssl-o1)
                (close-input-port ssl-i1)
                (close-output-port ssl-o1))))
                
                
    
     (let-values ([(ssl-i2 ssl-o2) (ports->ssl-ports i2 o1 #:context client-context #:close-original? #t)])
       (write-byte 100 ssl-o2)
       (close-output-port ssl-o2)
      (check-equal? (read ssl-i2) 100)
       (close-input-port ssl-i2))
              
     (when (= (modulo count 100) 0)
         (printf "~v connections done~n" count))
     
    (loop (add1 count)))))