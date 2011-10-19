#lang racket/base

(require (for-syntax racket/base)
         ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/atomic
         racket/port
         racket/tcp
         racket/list
         "libcrypto.rkt"
         "libssl.rkt"
         (planet okcomps/mailbox))

(provide ssl-available?
         ssl-load-fail-reason
         
         ssl-make-client-context
         ssl-make-server-context
         ssl-client-context?
         ssl-server-context?
         ssl-context?
         
         ssl-load-certificate-chain!
         ssl-load-private-key!
         ssl-load-verify-root-certificates!
         ssl-load-suggested-certificate-authorities!
         
         ssl-set-verify!
         
         ;sets the ssl server to attempt verification of certificates
         ;it does not require verification though.
         ssl-try-verify!
         
         ;call on an ssl port, this will return true if the peer
         ;presented a valid certificate and was verified
         ssl-peer-verified?
         ssl-peer-subject-name
         ssl-peer-issuer-name
         
         ports->ssl-ports
         
         ssl-listen
         ssl-close
         ssl-accept
         ssl-accept/enable-break
         ssl-connect
         ssl-connect/enable-break
         
         ssl-listener?
         ssl-addresses
         ssl-abandon-port
         
         ssl-port?)

(define ssl-load-fail-reason
  (or libssl-load-fail-reason
      libcrypto-load-fail-reason))

(define 3m? (eq? '3m (system-type 'gc)))

(define libmz (ffi-lib #f))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSL bindings and constants

(define-ffi-definer define-crypto libcrypto
  #:default-make-fail make-not-available)
(define-ffi-definer define-ssl libssl
  #:default-make-fail make-not-available)
(define-ffi-definer define-mzscheme libmz)

(define-syntax typedef
  (syntax-rules ()
    [(_ id t)
     (define-fun-syntax id (syntax-id-rules () [_ t]))]))

(typedef _BIO_METHOD* _pointer)
(typedef _BIO* _pointer)
(typedef _SSL_METHOD* _pointer)
(typedef _SSL_CTX* _pointer)
(typedef _SSL* _pointer)
(typedef _X509_NAME* _pointer)
(typedef _X509* _pointer)

(define-ssl SSLv2_client_method (_fun -> _SSL_METHOD*))
(define-ssl SSLv2_server_method (_fun -> _SSL_METHOD*))
(define-ssl SSLv3_client_method (_fun -> _SSL_METHOD*))
(define-ssl SSLv3_server_method (_fun -> _SSL_METHOD*))
(define-ssl SSLv23_client_method (_fun -> _SSL_METHOD*))
(define-ssl SSLv23_server_method (_fun -> _SSL_METHOD*))
(define-ssl TLSv1_client_method (_fun -> _SSL_METHOD*))
(define-ssl TLSv1_server_method (_fun -> _SSL_METHOD*))

(define-crypto BIO_s_mem (_fun -> _BIO_METHOD*))
(define-crypto BIO_new (_fun _BIO_METHOD* -> _BIO*))
(define-crypto BIO_free (_fun _BIO* -> _void))
(define-crypto BIO_ctrl_pending (_fun _BIO* -> _int))

(define-crypto BIO_read (_fun _BIO* _bytes _int -> _int))
(define-crypto BIO_write (_fun _BIO* _bytes _int -> _int))
(define-crypto BIO_ctrl (_fun _BIO* _int _long _long -> _long))
(define (BIO_set_mem_eof_return b v)
  (BIO_ctrl b BIO_C_SET_BUF_MEM_EOF_RETURN v 0))

(define-ssl SSL_CTX_new (_fun _SSL_METHOD* -> _SSL_CTX*))
(define-ssl SSL_CTX_free (_fun _SSL_CTX* -> _void))
(define-ssl SSL_CTX_ctrl (_fun _SSL_CTX* _int _long _pointer -> _long))
(define (SSL_CTX_set_mode ctx m)
  (SSL_CTX_ctrl ctx SSL_CTRL_MODE m #f))

(define-ssl SSL_CTX_set_verify (_fun _SSL_CTX* _int _pointer -> _void))
(define-ssl SSL_CTX_use_certificate_chain_file (_fun _SSL_CTX* _bytes -> _int))
(define-ssl SSL_CTX_load_verify_locations (_fun _SSL_CTX* _bytes _pointer -> _int))
(define-ssl SSL_CTX_set_client_CA_list (_fun _SSL_CTX* _X509_NAME* -> _int))
(define-ssl SSL_CTX_set_session_id_context (_fun _SSL_CTX* _bytes _int -> _int))
(define-ssl SSL_CTX_use_RSAPrivateKey_file (_fun _SSL_CTX* _bytes _int -> _int))
(define-ssl SSL_CTX_use_PrivateKey_file (_fun _SSL_CTX* _bytes _int -> _int))
(define-ssl SSL_load_client_CA_file (_fun _bytes -> _X509_NAME*))

(define-ssl SSL_new (_fun _SSL_CTX* -> _SSL*))
(define-ssl SSL_set_bio (_fun _SSL* _BIO* _BIO* -> _void))
(define-ssl SSL_connect (_fun _SSL* -> _int))
(define-ssl SSL_accept (_fun _SSL* -> _int))
(define-ssl SSL_free (_fun _SSL* -> _void))
(define-ssl SSL_read (_fun _SSL* _bytes _int -> _int))
(define-ssl SSL_write (_fun _SSL* _bytes _int -> _int))
(define-ssl SSL_shutdown (_fun _SSL* -> _int))
(define-ssl SSL_get_verify_result (_fun _SSL* -> _long))
(define-ssl SSL_get_peer_certificate (_fun _SSL* -> _X509*))
(define-ssl SSL_state (_fun _SSL* -> _int))
(define-ssl SSL_state_string (_fun _SSL* -> _bytes))


(define-crypto X509_get_subject_name (_fun _X509* -> _X509_NAME*))
(define-crypto X509_get_issuer_name (_fun _X509* -> _X509_NAME*))
(define-crypto X509_NAME_oneline (_fun _X509_NAME* _bytes _int -> _bytes))

(define-ssl SSL_get_error (_fun _SSL* _int -> _int))

(define-crypto ERR_get_error (_fun -> _long))
(define-crypto ERR_error_string_n (_fun _long _bytes _long -> _void))

(define-ssl SSL_library_init (_fun -> _void))
(define-ssl SSL_load_error_strings (_fun -> _void))

(define X509_V_OK 0)

(define SSL_ERROR_NONE 0)
(define SSL_ERROR_SSL 1)
(define SSL_ERROR_WANT_READ 2)
(define SSL_ERROR_WANT_WRITE 3)
(define SSL_ERROR_SYSCALL 5)
(define SSL_ERROR_ZERO_RETURN 6)


(define (SSL_ERROR->symbol code)
  (cond
    [(equal? code SSL_ERROR_NONE) 'SSL_ERROR_NONE]
    [(equal? code SSL_ERROR_SSL) 'SSL_ERROR_SSL]
    [(equal? code SSL_ERROR_WANT_READ) 'SSL_ERROR_WANT_READ]
    [(equal? code SSL_ERROR_WANT_WRITE) 'SSL_ERROR_WANT_WRITE]
    [(equal? code SSL_ERROR_SYSCALL) 'SSL_ERROR_SYSCALL]
    [(equal? code SSL_ERROR_ZERO_RETURN) 'SSL_ERROR_ZERO_RETURN]
    [else (error 'SSL_ERROR->symbol (format "unkown error ~v" code))]))


(define SSL_OK 3)

(define BIO_C_SET_BUF_MEM_EOF_RETURN 130)

(define SSL_FILETYPE_PEM 1)
(define SSL_FILETYPE_ASN1 2)

(define SSL_VERIFY_NONE #x00)
(define SSL_VERIFY_PEER #x01)
(define SSL_VERIFY_FAIL_IF_NO_PEER_CERT #x02)

(define SSL_MODE_ENABLE_PARTIAL_WRITE #x01)
(define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER #x02)
(define SSL_CTRL_MODE 33)

(define-mzscheme scheme_start_atomic (_fun -> _void))
(define-mzscheme scheme_end_atomic (_fun -> _void))
(define-mzscheme scheme_make_custodian (_fun _pointer -> _scheme))

;; Make this bigger than 4096 to accommodate at least
;; 4096 of unencrypted data
(define BUFFER-SIZE 16384)

;; The man pages for SSL_read and SSL_write say that they must be
;; retried with the same arguments when they return SSL_ERROR_WANT_READ
;; or SSL_ERROR_WANT_WRITE.  This may not actually be true, especially
;; when SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is used, and "retry" may or
;; may not mean "retry without doing other things first". Set `enforce-retry?'
;; to #t to obey the manpage and retry without doing other things, which
;; has an implicitation for clients as noted at the top of this file.
(define enforce-retry? #f)


;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Debug logging for development purposes

(define-for-syntax enable-ssl-logging #t)

(define-syntax (log-ssl stx)
  (if enable-ssl-logging
      (syntax-case stx ()
        [(_ stx ...)
         #'(log-debug (format stx ...))])
      #'(void)))


;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Error handling

(define-syntax with-failure
  (syntax-rules ()
    [(_ thunk body ...)
     (with-handlers ([exn? (lambda (exn)
                             (thunk)
                             (raise exn))])
       body ...)]))

(define (get-error-message id)
  (let* ([buffer (make-bytes 512)])
    (ERR_error_string_n id buffer (bytes-length buffer))
    (regexp-match #rx#"^[^\0]*" buffer)))

(define (check-valid v who what)
  (when (ptr-equal? v #f)
    (let ([id (ERR_get_error)])
      (escape-atomic
       (lambda ()
         (error who "~a failed ~a" what (get-error-message id)))))))

(define (error/network who fmt . args)
  (raise (make-exn:fail:network
          (format "~a: ~a" who (apply format fmt args))
          (current-continuation-marks))))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Atomic blocks

;; Obviously, be careful in an atomic block. In particular,
;; DO NOT CONSTRUCT AN ERROR DIRECTLY IN AN ATOMIC BLOCK,
;; because the error message almost certainly involves things
;; like a ~a or ~e format, which can trigger all sorts of
;; printing extensions. Instead, send a thunk that
;; constructs and raises the exception to `escape-atomic'.

(define in-atomic? (make-parameter #f))
(struct exn:atomic exn (thunk))

(define-syntax atomically
  (syntax-rules ()
    [(_ body ...)
     (parameterize-break
      #f
      (with-handlers ([exn:atomic? (lambda (exn)
                                     ((exn:atomic-thunk exn)))])
        (parameterize ([in-atomic? #t])
          (dynamic-wind
           (lambda () (scheme_start_atomic))
           (lambda () body ...)
           (lambda () (scheme_end_atomic))))))]))

(define (escape-atomic thunk)
  (if (in-atomic?)
      (raise (exn:atomic 
              "error during atomic..."
              (current-continuation-marks)
              thunk))
      (thunk)))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Structs

(struct ssl-context (ctx))
(struct ssl-client-context ssl-context ())
(struct ssl-server-context ssl-context ())

(struct ssl-listener (l mzctx)
  #:property prop:evt (lambda (lst) (wrap-evt (ssl-listener-l lst) 
                                              (lambda (x) lst))))


(struct ssl-port (ssl pump cypher-port))

(struct ssl-input-port ssl-port (clear-port)
  #:property prop:input-port (struct-field-index clear-port))

(struct ssl-output-port ssl-port (clear-port)
  #:property prop:output-port (struct-field-index clear-port))

(define (make-immobile-bytes n)
  (if 3m?
      ;; Allocate the byte string via malloc:
      (atomically
       (let* ([p (malloc 'raw n)]
              [s (make-sized-byte-string p n)])
         (register-finalizer s (lambda (v)
                                 (log-ssl "openssl: freed immobile bytes")
                                 (free p)))
         (log-ssl "openssl: made immobile bytes")
         s))
      (make-bytes n)))


(define (make-SSL_CTX who meth)
  (atomically
   (let ([ctx (SSL_CTX_new meth)])
     (check-valid ctx who "context creation")
     (register-finalizer ctx (lambda (v)
                               (log-ssl "openssl: freed ssl context")
                               (SSL_CTX_free v)))
     (log-ssl "openssl: made ssl context")
     ctx)))

(define (make-SSL who ctx)
  (atomically
   (let ([ssl (SSL_new ctx)])
     (check-valid ssl who "make-SSL")
     (register-finalizer ssl
                         (lambda (v)
                           (log-ssl "openssl: freed ssl")
                           (SSL_free v)))
     (log-ssl "openssl: made ssl")
     ssl)))


;TODO, make cancel box to ensure mem-bios get freed
(define (make-mem-bio who)
  (atomically
   (let ([bio (BIO_new (BIO_s_mem))])
     (check-valid bio who "make-mem-bio")
     #|(register-finalizer bio (lambda (v)
                               (log-debug (format "openssl(~a): freed mem bio" (current-ssl-connection-id)))
                               (BIO_free v)))|#
     (log-ssl "openssl: made mem bio")
     bio)))


;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Contexts, certificates, etc.

(define default-encrypt 'sslv2-or-v3)

(define (encrypt->method who also-expect e client?)
  ((case e
     [(sslv2-or-v3) (if client?
                        SSLv23_client_method
                        SSLv23_server_method)]
     [(sslv2) (if client?
                  SSLv2_client_method
                  SSLv2_server_method)]
     [(sslv3) (if client?
                  SSLv3_client_method
                  SSLv3_server_method)]
     [(tls) (if client?
                TLSv1_client_method
                TLSv1_server_method)]
     [else (escape-atomic
            (lambda ()
              (raise-type-error 
               who
               (string-append also-expect "'sslv2-or-v3, 'sslv2, 'sslv3, or 'tls")
               e)))])))

(define (make-context who protocol-symbol also-expected client?)
  (let* ([meth (encrypt->method who also-expected protocol-symbol client?)]
         [ctx (make-SSL_CTX who meth)])
    (SSL_CTX_set_mode ctx (bitwise-ior SSL_MODE_ENABLE_PARTIAL_WRITE
                                       SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER))   
    ((if client? ssl-client-context ssl-server-context) ctx)))

(define (ssl-make-client-context [protocol-symbol default-encrypt])
  (make-context 'ssl-make-client-context protocol-symbol "" #t))

(define (ssl-make-server-context [protocol-symbol default-encrypt])
  (make-context 'ssl-make-server-context protocol-symbol "" #f))

(define (get-context who context-or-encrypt-method client?)
  (if (ssl-context? context-or-encrypt-method)
      (ssl-context-ctx context-or-encrypt-method)
      (let ([ctx (make-context who encrypt->method who "context" context-or-encrypt-method client?)])
        (SSL_CTX_set_mode ctx SSL_MODE_ENABLE_PARTIAL_WRITE)
        ctx)))

(define (get-context/listener who ssl-context-or-listener)
  (cond
    [(ssl-context? ssl-context-or-listener)
     (ssl-context-ctx ssl-context-or-listener)]
    [(ssl-listener? ssl-context-or-listener)
     (ssl-context-ctx (ssl-listener-mzctx ssl-context-or-listener))]
    [else
     (raise-type-error who
                       "SSL context or listener"
                       ssl-context-or-listener)]))

(define (ssl-load-... who load-it ssl-context-or-listener pathname)
  (let ([ctx (get-context/listener 'ssl-load-certificate-chain!
                                   ssl-context-or-listener)])
    (unless (path-string? pathname)
      (raise-type-error 'ssl-load-certificate-chain!
                        "path or string"
                        pathname))
    (let ([path (path->bytes
                 (path->complete-path (cleanse-path pathname)
                                      (current-directory)))])
      (let ([n (load-it ctx path)])
        (unless (= n 1)
          (error who "load failed from: ~e ~a"
                 pathname
                 (get-error-message (ERR_get_error))))))))

(define (ssl-load-certificate-chain! ssl-context-or-listener pathname)
  (ssl-load-... 'ssl-load-certificate-chain! 
                SSL_CTX_use_certificate_chain_file
                ssl-context-or-listener pathname))

(define (ssl-load-verify-root-certificates! ssl-context-or-listener pathname)
  (ssl-load-... 'ssl-load-verify-root-certificates! 
                (lambda (a b) (SSL_CTX_load_verify_locations a b #f))
                ssl-context-or-listener pathname))

(define (ssl-load-suggested-certificate-authorities! ssl-listener pathname)
  (ssl-load-... 'ssl-load-suggested-certificate-authorities! 
                (lambda (ctx path)
                  (let ([stk (SSL_load_client_CA_file path)])
                    (if (ptr-equal? stk #f)
                        0
                        (begin
                          (SSL_CTX_set_client_CA_list ctx stk)
                          1))))
                ssl-listener pathname))

(define (ssl-load-private-key! ssl-context-or-listener pathname
                               [rsa? #t] [asn1? #f])
  (ssl-load-...
   'ssl-load-private-key!
   (lambda (ctx path)
     ((if rsa? SSL_CTX_use_RSAPrivateKey_file SSL_CTX_use_PrivateKey_file)
      ctx path
      (if asn1? SSL_FILETYPE_ASN1 SSL_FILETYPE_PEM)))
   ssl-context-or-listener pathname))

(define (ssl-set-verify! ssl-context-or-listener on?)
  (let ([ctx (get-context/listener 'ssl-set-verify!
                                   ssl-context-or-listener)])
    (SSL_CTX_set_verify ctx
                        (if on?
                            (bitwise-ior SSL_VERIFY_PEER 
                                         SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                            SSL_VERIFY_NONE)
                        #f)))

(define (ssl-try-verify! ssl-context-or-listener on?)
  (let ([ctx (get-context/listener 'ssl-set-verify!
                                   ssl-context-or-listener)])
    
    ;required by openssl. This is more for when calling i2d_SSL_SESSION/d2i_SSL_SESSION
    ;for instance if we were saving sessions in a database etc... We aren't using that
    ;so a generic session name should be fine.
    (let ([bytes #"racket"])
      (SSL_CTX_set_session_id_context ctx bytes (bytes-length bytes)))
    
    (SSL_CTX_set_verify ctx
                        (if on?
                            SSL_VERIFY_PEER
                            SSL_VERIFY_NONE)
                        #f)))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSL ports



(define (pump-thread-notify thd message fail-thunk)
  (let ([channel (make-channel)]
        [dead-evt (thread-dead-evt thd)])
    (thread-send thd (cons message channel) #f)
    (let ([result (sync channel dead-evt)])
      (log-ssl "pump-thread-notify result ~v" result)
      (if (equal? result dead-evt)
          (fail-thunk)
          result))))




(define (flush-ssl ssl-pump-thread)
  (pump-thread-notify ssl-pump-thread 'flush (λ () void)))


(define (ports->ssl-ports i o 
                          #:context [context #f]
                          #:encrypt [encrypt default-encrypt]
                          #:mode [mode 'connect]
                          #:close-original? [close-original? #f]
                          #:error/ssl [error/ssl error])
  (wrap-ports 'port->ssl-ports i o (or context encrypt) mode close-original? error/ssl))

(define (create-ssl who context-or-encrypt-method connect/accept error/ssl)
  (let* ([connect? (case connect/accept
                     [(connect) #t]
                     [(accept) #f]
                     [else
                      (raise-type-error who "'connect or 'accept" 
                                        connect/accept)])]
         [ctx (get-context who context-or-encrypt-method (eq? connect/accept 'connect))]
         [ssl (make-SSL who ctx)])
    (values ssl error connect?)))


(define current-ssl-connection-id (make-parameter #f))

(define (wrap-ports who i o context-or-encrypt-method connect/accept close? error/ssl)
  (unless (input-port? i)
    (raise-type-error who "input port" i))
  (unless (output-port? o)
    (raise-type-error who "output port" o))
  
  (current-ssl-connection-id (random 4294967087))
  
  ;ssl-context ;ssl connection context this input-pump belongs to
  ;read-bio ;the bio that SSL_read reads from
  ;write-bio ;the bio that SSL_write writes to
  ;cypher-port-in ;comes in from the other side of the connection
  ;cypher-port-out ;goes over the wire to the other side of the connection
  ;clear-port-in  ;data comes from the application over this
  ;clear-port-out ;data goes out to the application over this
  
  (let*-values ([(clear-from-pipe-in clear-from-pipe-out) (make-pipe)] ;pipes data in from the application
                [(clear-to-pipe-in clear-to-pipe-out) (make-pipe)] ;pipes data out to the application
                [(ssl cancel connect?) (create-ssl who context-or-encrypt-method connect/accept error/ssl)]
                [(ssl-pump-thread) (thread (λ () 
                                             (ssl-pump ssl i o clear-from-pipe-in clear-to-pipe-out close? (if connect? SSL_connect SSL_accept))))])
    
    
    ;TODO: need to capture when the application closes its output port
    ;we know when the input port is closed, because we eventually get an EOF on the out side
    
    
    (pump-thread-notify ssl-pump-thread 'connect 
                        (λ ()
                          (error/ssl who "~a failed to connect"
                                     (if connect? "connect" "accept"))))
    
    (log-ssl "openssl: new connection established")
    (values (ssl-input-port ssl 
                            ssl-pump-thread 
                            i 
                            (make-input-port
                             'ssl-input-port
                             (λ (bstr)
                               (let ([result (read-bytes-avail!* bstr clear-to-pipe-in)])
                                 (if (equal? result 0)
                                     (wrap-evt clear-to-pipe-in (λ (x) x))
                                     result)))
                             #f
                             (λ ()
                               (log-ssl "ssl-port: input port closed")
                               (close-input-port clear-to-pipe-in)
                               (thread-send ssl-pump-thread 'input-port-closed #f))))
                             
            
            (ssl-output-port ssl 
                             ssl-pump-thread 
                             o
                             (make-output-port
                              'ssl-output-port
                              always-evt
                              (λ (bstr start end non-block? breakable?)
                                ((cond [non-block? write-bytes-avail*]
                                       [breakable? write-bytes-avail/enable-break]
                                       [else write-bytes-avail])
                                 bstr 
                                 clear-from-pipe-out 
                                 start 
                                 end))
                              (λ ()
                                (log-ssl "ssl-port: output port closed")
                                (close-output-port clear-from-pipe-out)
                                (flush-ssl ssl-pump-thread)))))))



;pumps data between the pipes, ssl, memory bios, etc...
(define (ssl-pump ssl-context ;ssl connection context this input-pump belongs to
                  cypher-port-in ;comes in from the other side of the connection
                  cypher-port-out ;goes over the wire to the other side of the connection
                  clear-port-in  ;data comes from the application over this
                  clear-port-out ;data goes out to the application over this
                  close-original? ;close down the original input and output ports when the ssl operation ends
                  connect) ;connect or accept connection

  ;this is volatile in the sense that it is used in
  ;3 or 4 different places and will be overwritten between iterations of the loop
  (define xfer-buffer (make-immobile-bytes BUFFER-SIZE))
  
  ;the bio that SSL_read reads from
  (define read-bio (make-mem-bio 'ssl-pump))
  
  ;the bio that SSL_write writes to
  (define write-bio (make-mem-bio 'ssl-pump))
  
  ;setup the ssl-context to use the read and write bios
  (SSL_set_bio ssl-context read-bio write-bio)
  
  ;what to do when we are finished up
  (define (halt)
    (close-input-port clear-port-in)
    (close-output-port clear-port-out)
    (when close-original? 
      (close-input-port cypher-port-in)
      (close-output-port cypher-port-out)
      (log-ssl "ssl-pump: closed original ports"))
    (log-ssl "ssl-pump: halted")
    (kill-thread (current-thread)))
  
  
  ;execute the connection function
  ;it will be SSL_connect or SSL_accept
  (connect ssl-context)
  
  
  (let main-loop ([state SSL_ERROR_NONE]  ;the last known ERROR state when calling SSL_read and SSL_write
                  [abandon-port? #f] ;tracks when the application calls ssl-abandon-port on the client port
                  [flushes empty] ;tracks any threads waiting on flushes
                  [connect-channel #f]) ;tracks the thread that is waiting for a connection to complete
    
    (let ([state-clear-port-in (cond [(port-closed? clear-port-in)
                                      'closed]
                                     [(byte-ready? clear-port-in)
                                      'ready]
                                     [else
                                      'not-ready])]
          [state-clear-port-out (cond [(port-closed? clear-port-out)
                                       'closed]
                                      [else
                                       'open])]
          [state-cypher-port-in (cond [(port-closed? cypher-port-in)
                                      'closed]
                                     [(byte-ready? cypher-port-in)
                                      'ready]
                                     [else
                                      'not-ready])]
          [state-bio-write-bytes (BIO_ctrl_pending write-bio)]
          [state-bio-read-bytes (BIO_ctrl_pending read-bio)]
          
          [state-ssl-error (SSL_ERROR->symbol state)]
          [state-ssl-state-string (SSL_state_string ssl-context)]
          [state-pending-flush-count (length flushes)])
    
      (log-ssl "ssl-pump: entering loop: clear-port-in:(~v) clear-port-out:(~v) cypher-port-in:(~v) write-bio bytes:(~v) read-bio bytes:(~v) state:(~v) ssl_state:(~v) flushes-pending:(~v)"
                         state-clear-port-in
                         state-clear-port-out
                         state-cypher-port-in
                         state-bio-write-bytes
                         state-bio-read-bytes
                         state-ssl-error
                         state-ssl-state-string
                         state-pending-flush-count)
    
    ;from here we are going to determine what to do next
    ;we operate as a great big state machine depending upon what events occur
    (receive 
     
     ;exit out if something bad happened
     [(when (or (equal? state SSL_ERROR_SSL)
                (equal? state SSL_ERROR_SYSCALL)))
      (log-debug (format "ssl-pump: error ~v. exiting." state))
      (halt)]
     
     
     ;if we are in state SSL_ERROR_ZERO_RETURN
     ;it means an SSL shutdown has occured cleanly and we can exit
     [(when (equal? state SSL_ERROR_ZERO_RETURN))
      (log-ssl "ssl-pump: connection closed")
      (halt)]
     
     ;check the write bio for any info that must be pumped out
     ;if ssl has some encoded data that has to get written to the cypher port
     ;push it out over the wire
     [(when (> state-bio-write-bytes 0))
      (let ([written (BIO_read write-bio xfer-buffer BUFFER-SIZE)])
        (write-bytes xfer-buffer cypher-port-out 0 written)
        (flush-output cypher-port-out)
        (log-ssl "ssl-pump: wrote ~v bytes cyphertext to cypher out" written))
      (main-loop state abandon-port? flushes connect-channel)]
     
     ;if there are any bytes in the read bio that need unencoded
     ;we must perform a read
     [(when (> state-bio-read-bytes 0))
      (main-loop (let* ([ssl-count (SSL_read ssl-context xfer-buffer BUFFER-SIZE)])
                   (if (> ssl-count 0)
                       ;write the data out and loop
                       (begin
                         (write-bytes xfer-buffer clear-port-out 0 ssl-count)
                         (flush-output clear-port-out)
                         (log-ssl "ssl-pump: wrote ~v bytes to clear-port-out" ssl-count)
                         SSL_ERROR_NONE)
                       
                       ;we failed to write data, something could have happend
                       ;that requires further action before we can read more
                       ;data
                       (SSL_get_error ssl-context ssl-count)))
                 abandon-port?
                 flushes
                 connect-channel)]
        
     
     ;has data arrived from the application?
     [(event (guard-evt (λ () (if (port-closed? clear-port-in) never-evt clear-port-in))))
      ;we peek the bytes off and try to write them
      (let* ([progress (port-progress-evt clear-port-in)]
             [in-count (peek-bytes-avail! xfer-buffer 0 progress clear-port-in)])
        
        (if (equal? eof in-count)
            (begin
              ;if we get an eof, it means the output port
              ;on the clear side was closed by the application
              (log-ssl "ssl-pump: clear-port-in closed")
              (close-input-port clear-port-in)
              (main-loop state  
                         abandon-port?
                         flushes
                         connect-channel))
            (let ([ssl-count (SSL_write ssl-context xfer-buffer in-count)])
              (log-ssl "ssl-pump: read ~a bytes from clear-port-in" in-count)
              ;the write succeeded, we can remove the peeked bytes from clear-port-in
              ;that we previously peeked
              (port-commit-peeked ssl-count progress always-evt clear-port-in)
              (log-ssl "ssl-pump: SSL_write: wrote ~a bytes to ssl" ssl-count)
              (main-loop (if (> ssl-count 0) SSL_ERROR_NONE (SSL_get_error ssl-context ssl-count))
                         abandon-port?
                         flushes
                         connect-channel))))]
     
     
     ;any data from the cypher text port?
     ;push it into the BIO
     [(event cypher-port-in)
      (let ([in-count (read-bytes-avail! xfer-buffer cypher-port-in)])
        (if (equal? eof in-count)
            (begin
              ;if eof is returned on the input port
              ;we can never proceed further and halt
              (log-ssl "ssl-pump: cypher-port-in closed - shutting down")
              (close-input-port cypher-port-in)
              (halt))
            (let ([bio-count (BIO_write read-bio xfer-buffer in-count)])
              (unless (= in-count bio-count)
                (error 'input-pump "ssl-pump: Bio write seemed to fail!"))

              (log-ssl "ssl-pump: read ~a bytes from cypher-port-in" in-count)
              
              (main-loop state abandon-port? flushes connect-channel))))]
        
     
     ;when abandon-port? is true we won't be performing an ssl shutdown
     ;if both application ports are closed
     ;then there is no possibility of further communication
     [(when (and abandon-port? 
                 (port-closed? clear-port-in)
                 (port-closed? clear-port-out)))
      (halt)]
     
     ;when both application ports are closed
     ;we initiate an ssl shutdown sequence
     [(when (and (not abandon-port?)
                 (port-closed? clear-port-in)
                 (port-closed? clear-port-out)
                 (= state-bio-write-bytes 0)
                 (not (eq? state-cypher-port-in 'ready))
                 (not (or (equal? state SSL_ERROR_WANT_READ) (equal? state SSL_ERROR_WANT_WRITE)))))
      (let ([result (SSL_shutdown ssl-context)])
        (log-ssl "ssl-pump: ssl-shudown result ~v" result)
        (cond [(equal? result 1)
               (log-ssl "ssl-pump: ssl shutdown successful")
               (halt)]
              [(equal? result 0)
               (log-ssl "ssl-pump: ssl shutdown pending")
               (main-loop state abandon-port? flushes #f)]
              [else
               (log-ssl "ssl-pump: ssl shutdown not finished")
               (main-loop (SSL_get_error ssl-context result)
                          abandon-port?
                          flushes
                          connect-channel)]))]
     
     ;when ssl goes SSL_OK
     ;we can now notify the thread waiting on us to completed the connection
     [(when (and connect-channel (equal? (SSL_state ssl-context) SSL_OK)))
      (log-ssl "ssl-pump: sent connection ok to waiting connect")
      (channel-put connect-channel 'ok)
      (main-loop state abandon-port? flushes #f)]
     
     
     ;notify any threads waiting for a flush that all data has been committed
     ;to the underlying write port
     [(when (and (not (empty? flushes))
                 (or (port-closed? clear-port-in) (equal? state-clear-port-in 'not-ready))
                 (= state-bio-write-bytes 0)))
      (for-each (λ (flush-channel)
                  (channel-put flush-channel 'ok)
                  (log-ssl "ssl-pump: sent 'ok to flush channel ~v" flush-channel))
                flushes)
      (log-ssl "ssl-pump: flush completed")
      (main-loop state abandon-port? empty connect-channel)]
     
     
     ['input-port-closed
      ;since the application closed its input port, we will no longer
      ;be able to send anything to it, we can close our output port
      (close-output-port clear-port-out)
      (log-ssl "ssl-pump: received message: input-port-closed")
      (main-loop state abandon-port? flushes connect-channel)]
     
     [(cons 'abandon abandon-channel)
      (log-ssl "ssl-pump: received message: abandon-port")
      (channel-put abandon-channel 'ok)
      (main-loop state #t flushes connect-channel)]
     
     [(cons 'flush flush-channel)
      (log-ssl "ssl-pump: received flush message")
      (main-loop state abandon-port? (cons flush-channel flushes) connect-channel)]
     
     [(cons 'connect connect-channel)
      (log-ssl "ssl-pump: receive connect message")
      (main-loop state abandon-port? flushes connect-channel)]))))



(define (ssl-addresses port/listener [port-numbers? #f])
  (tcp-addresses  (if (ssl-listener? port/listener)
                      (ssl-listener-l port/listener)
                      (ssl-port-cypher-port port/listener))
                  port-numbers?))

(define (ssl-abandon-port p)
  (let ([pump-thread (ssl-port-pump p)])
    (pump-thread-notify pump-thread 'abandon (λ () (void)))))

(define (ssl-peer-verified? p)
  (let ([ssl (ssl-port-ssl p)])
    (and (eq? X509_V_OK (SSL_get_verify_result ssl))
         (SSL_get_peer_certificate ssl)
         #t)))

(define (ssl-peer-subject-name p)
  (let* ([ssl (ssl-port-ssl p)]
         [cert (SSL_get_peer_certificate ssl)])
    (if cert
        (let ([bytes (make-bytes 1024 0)])
          (X509_NAME_oneline (X509_get_subject_name cert) bytes (bytes-length bytes)))
        #f)))

(define (ssl-peer-issuer-name p)
  (let* ([ssl (ssl-port-ssl p)]
         [cert (SSL_get_peer_certificate ssl)])
    (if cert
        (let ([bytes (make-bytes 1024 0)])
          (X509_NAME_oneline (X509_get_issuer_name cert) bytes (bytes-length bytes)))
        #f)))


;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSL listen

(define (ssl-listen port-k
                    [queue-k 5] [reuse? #f] [hostname-or-#f #f]
                    [protocol-symbol-or-context default-encrypt])
  (let* ([ctx (if (ssl-server-context? protocol-symbol-or-context)
                  protocol-symbol-or-context
                  (make-context 'ssl-listen protocol-symbol-or-context
                                "server context, " #f))]
         [l (tcp-listen port-k queue-k reuse? hostname-or-#f)])
    (log-ssl "openssl: listening on port ~a" port-k)
    (ssl-listener l ctx)))

(define (ssl-close l)
  (unless (ssl-listener? l)
    (raise-type-error 'ssl-close "SSL listener" l))
  (log-ssl "openssl: closed listener")
  (tcp-close (ssl-listener-l l)))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSL accept

(define (do-ssl-accept who tcp-accept ssl-listener)
  (log-ssl "openssl: accepting connection")
  (let-values ([(i o) (tcp-accept (ssl-listener-l ssl-listener))])
    ;; Obviously, there's a race condition between accepting the
    ;; connections and installing the exception handler below. However,
    ;; if breaks are enabled, then i and o could get lost between
    ;; the time that tcp-accept returns and `i' and `o' are bound,
    ;; anyway. So we can assume that breaks are enabled without loss
    ;; of (additional) resources.
    (with-handlers ([void (lambda (exn)
                            (close-input-port i)
                            (close-output-port o)
                            (raise exn))])
      (log-ssl "openssl: wrapping ports")
      (wrap-ports who i o (ssl-listener-mzctx ssl-listener) 'accept #t error/network))))

(define (ssl-accept ssl-listener)
  (do-ssl-accept 'ssl-accept tcp-accept ssl-listener))

(define (ssl-accept/enable-break ssl-listener)
  (do-ssl-accept 'ssl-accept/enable-break tcp-accept/enable-break ssl-listener))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSL connect

(define (do-ssl-connect who tcp-connect hostname port-k client-context-or-protocol-symbol)
  (let-values ([(i o) (tcp-connect hostname port-k)])
    ;; See do-ssl-accept for note on race condition here:
    (with-handlers ([void (lambda (exn)
                            (close-input-port i)
                            (close-output-port o)
                            (raise exn))])
      (wrap-ports who i o client-context-or-protocol-symbol 'connect #t error/network))))

(define (ssl-connect
         hostname port-k
         [client-context-or-protocol-symbol default-encrypt])
  (do-ssl-connect 'ssl-connect
                  tcp-connect
                  hostname
                  port-k
                  client-context-or-protocol-symbol))

(define (ssl-connect/enable-break
         hostname port-k
         [client-context-or-protocol-symbol default-encrypt])
  (do-ssl-connect 'ssl-connect/enable-break
                  tcp-connect/enable-break
                  hostname
                  port-k
                  client-context-or-protocol-symbol))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Initialization

(define ssl-available? (and libssl #t))


(define scheme_register_process_global
  (and ssl-available?
       (get-ffi-obj 'scheme_register_process_global #f (_fun _string _pointer -> _pointer))))


(when ssl-available?
  ;; Make sure only one place tries to initialize OpenSSL,
  ;; and wait in case some other place is currently initializing
  ;; it.
  (begin
    (start-atomic)
    (let* ([done (cast 1 _scheme _pointer)]
           [v (scheme_register_process_global "OpenSSL-support-initializing" done)])
      (if v
          ;; Some other place is initializing:
          (begin
            (end-atomic)
            (let loop ()
              (unless (scheme_register_process_global "OpenSSL-support-initialized" #f)
                (sleep 0.01) ;; busy wait! --- this should be rare
                (loop))))
          ;; This place must initialize:
          (begin
            (SSL_library_init)
            (SSL_load_error_strings)
            (scheme_register_process_global "OpenSSL-support-initialized" done)
            (end-atomic))))))
