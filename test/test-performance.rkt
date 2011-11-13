#lang racket/base


(require (planet okcomps/racket-test)
         "../main.rkt"
         ;openssl
         )


         

#| 
this test sends 1 byte back and forth between two endpoints
if does this 50,000 times.
|#
(define-performance-test back-and-forth
  (test-timeout 30000)
  
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)])
    (thread (λ ()
              (let-values ([(ssl-i1 ssl-o1) (ports->ssl-ports i1 o2 #:context server-context #:mode 'accept)])
                (let loop ()
                  (write-byte (read-byte ssl-i1) ssl-o1)
                  (loop)))))
                  
    (let-values ([(ssl-i2 ssl-o2) (ports->ssl-ports i2 o1 #:context client-context)])
      (time-iteration 
       (λ ()
         (let loop ([count 0])
           (unless (= count 50000)
             (write-byte 100 ssl-o2)
             (read-byte ssl-i2)
             (loop (add1 count)))))))))


#|
Defines the amount of time it takes to read (expt 2 26) bytes or 67MB through one way
|#
(define-performance-test upload-67MB
  (test-timeout 30000)
  
  (define goal-count (expt 2 26))
  
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (let*-values ([(i1 o1) (make-pipe)]
                [(i2 o2) (make-pipe)])
    (thread (λ ()
              (let-values ([(ssl-i1 ssl-o1) (ports->ssl-ports i1 o2 #:context server-context #:mode 'accept)])
                (let ([bytes (make-bytes (* 1024 16))])
                      (let loop ([count 0])
                        (if (>= count goal-count)
                            (write 100 ssl-o1)  
                            (let ([read-count (read-bytes! bytes ssl-i1)])
                              (loop (+ count read-count)))))))))
                  
    (let-values ([(ssl-i2 ssl-o2) (ports->ssl-ports i2 o1 #:context client-context)])
      (time-iteration 
       (λ ()
         (let ([bytes (make-bytes (* 1024 16))])
           (let loop ([count 0])
             (unless (>= count goal-count)
               (loop (+ count (write-bytes bytes ssl-o2)))))
           (read-byte ssl-i2)))))))