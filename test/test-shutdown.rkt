#lang racket/base



(require "../mzssl.rkt"
         rackunit
         (planet okcomps/racket-test))


;creates an ssl connection
(define (make-ssl-test-ports server-i-port server-o-port client-i-port client-o-port #:close-original? close-original)
  (define server-context (ssl-make-server-context))
  (ssl-load-private-key! server-context "../test.pem")
  (ssl-load-certificate-chain! server-context "../test.pem")
  
  (define client-context (ssl-make-client-context))
  (ssl-load-private-key! client-context "../test.pem")
  
  (define start-thread (current-thread))
  
  ;we must allow two threads
  ;each one waits on the other
  (thread (λ ()
            (let-values ([(server-ssl-i-port server-ssl-o-port) (ports->ssl-ports server-i-port server-o-port #:context server-context #:mode 'accept #:close-original? close-original)])
              (printf "server ready~n")
              (thread-send start-thread (cons server-ssl-i-port server-ssl-o-port)))))
  
  (let-values ([(client-ssl-i-port client-ssl-o-port) (ports->ssl-ports client-i-port client-o-port #:context client-context #:mode 'connect #:close-original? close-original)]
               [(server-ports) (thread-receive)])
    (printf "client ready~n")
    (values (car server-ports)
            (cdr server-ports)
            client-ssl-i-port
            client-ssl-o-port)))


(ssl-enable-verbose-logging #t)

(define-unit-test connection-test
  (let-values ([(i1 o1) (make-pipe)]
               [(i2 o2) (make-pipe)])
    (let-values ([(server-i server-o client-i client-o) (make-ssl-test-ports i1 o2 i2 o1 #:close-original? #t)])
      
      (write "hi" client-o)
      (close-output-port client-o)
      
      (printf "wrote hi to server")
      
      (let ([in (read server-i)])
        (printf "read ~v on server side~n" in)
        (check-equal? in "hi"))
      (close-input-port server-i)
      
      (write "hi" server-o)
      (printf "wrote \"hi\" on server output~n")
      (close-output-port server-o)
      
      (let ([in (read client-i)])
        (printf "read ~v on client input~n" in)
        (check-equal? in "hi"))
      
      ;now the read should return EOF
      ;because shutdown should have completed
      (printf "port closed? ~v~n" (port-closed? client-i))
      (let ([in (read client-i)])
        (printf "read ~v on client input~n" in)
        (check-equal? eof in))
      
      (close-input-port client-i))))

;simple send through and read back test
(define-unit-test shutdown-close-original
  (let-values ([(i1 o1) (make-pipe)]
               [(i2 o2) (make-pipe)])
    (let-values ([(server-i server-o client-i client-o) (make-ssl-test-ports i1 o2 i2 o1 #:close-original? #t)])
      
      (close-output-port server-o)
      (close-input-port server-i)
      
      ;port should be now closed after the shutdown occurs
      (check-equal? (read client-i) eof)
      
      (close-input-port client-i)
      (close-output-port client-o)
      
      (check-true (port-closed? i1))
      (check-true (port-closed? i2))
      
      (check-true (port-closed? o1))
      (check-true (port-closed? o2)))))


;simple send through and read back test
(define-unit-test shutdown-not-close-original
  (let-values ([(i1 o1) (make-pipe)]
               [(i2 o2) (make-pipe)])
    (let-values ([(server-i server-o client-i client-o) (make-ssl-test-ports i1 o2 i2 o1 #:close-original? #f)])
      
      (close-input-port server-i)
      (close-output-port server-o)
      
      ;port should be now closed after the shutdown occurs
      (check-equal? (read client-i) eof)
      
      (close-input-port client-i)
      (close-output-port client-o)
      
      (check-false (port-closed? i1))
      (check-false (port-closed? i2))
      
      (check-false (port-closed? o1))
      (check-false (port-closed? o2))
      
      ;there should be no garbage information on the underlying ports
      (check-false (byte-ready? i1))
      (check-false (byte-ready? i2)))))

;(connection-test)
(shutdown-close-original)
;(shutdown-not-close-original)

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