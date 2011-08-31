#lang racket/base

(require ffi/unsafe
         ffi/unsafe/define
         ffi/unsafe/atomic
         racket/port
         racket/tcp
         racket/list
         racket/async-channel
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
(define BUFFER-SIZE 8000)

;; The man pages for SSL_read and SSL_write say that they must be
;; retried with the same arguments when they return SSL_ERROR_WANT_READ
;; or SSL_ERROR_WANT_WRITE.  This may not actually be true, especially
;; when SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is used, and "retry" may or
;; may not mean "retry without doing other things first". Set `enforce-retry?'
;; to #t to obey the manpage and retry without doing other things, which
;; has an implicitation for clients as noted at the top of this file.
(define enforce-retry? #f)

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

;TODO: remove define struct
(struct ssl-context (ctx))
(struct ssl-client-context ssl-context ())
(struct ssl-server-context ssl-context ())

(struct ssl-listener (l mzctx)
  #:property prop:evt (lambda (lst) (wrap-evt (ssl-listener-l lst) 
                                              (lambda (x) lst))))


(struct ssl-port (mzssl))

(struct ssl-input-port ssl-port (port)
  #:property prop:input-port (struct-field-index port))

(struct ssl-output-port ssl-port (port)
  #:property prop:output-port (struct-field-index port))

;; internal:
(struct mzssl (ssl i o pump-thread))


(define (make-immobile-bytes n)
  (if 3m?
      ;; Allocate the byte string via malloc:
      (atomically
       (let* ([p (malloc 'raw n)]
              [s (make-sized-byte-string p n)])
         (register-finalizer s (lambda (v) 
                                 (log-debug "freed immobile bytes") 
                                 (free p)))
         (log-debug "made immobile bytes")
         s))
      (make-bytes n)))


(define (make-SSL_CTX who meth)
  (atomically
   (let ([ctx (SSL_CTX_new meth)])
     (check-valid ctx who "context creation")
     (register-finalizer ctx (lambda (v) 
                               (log-debug "freed ssl context")
                               (SSL_CTX_free v)))
     (log-debug "made ssl context")
     ctx)))

(define (make-SSL who ctx)
  (atomically
   (let ([ssl (SSL_new ctx)])
     (check-valid ssl who "make-SSL")
     (register-finalizer ssl
                         (lambda (v)
                           (log-debug "freed ssl")
                           (SSL_free ssl)))
     (log-debug "made ssl")
     ssl)))


(define (make-mem-bio who)
  (atomically
   (let ([bio (BIO_new (BIO_s_mem))])
     (check-valid bio who "make-mem-bio")
     (register-finalizer bio (lambda (v)
                               (log-debug "freed memory bio")
                               (BIO_free v)))
     (log-debug "made memory bio")
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
  (let ([channel (make-async-channel 1)]
        [dead-evt (thread-dead-evt thd)])
    (thread-send thd (cons message channel) #f)
    (let ([result (sync channel dead-evt)])
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
                          #:shutdown-on-close? [shutdown-on-close? #f]
                          #:error/ssl [error/ssl error])
  (wrap-ports 'port->ssl-ports i o (or context encrypt) mode close-original? shutdown-on-close? error/ssl))

(define (create-ssl who context-or-encrypt-method connect/accept error/ssl)
  (let* ([connect? (case connect/accept
                     [(connect) #t]
                     [(accept) #f]
                     [else
                      (raise-type-error who "'connect or 'accept" 
                                        connect/accept)])]
         [ctx (get-context who context-or-encrypt-method (eq? connect/accept 'connect))]
         [ssl (make-SSL who ctx)])
    ;; Return SSL and the cancel boxL:
    (values ssl error connect?)))

(define (wrap-ports who i o context-or-encrypt-method connect/accept close? shutdown-on-close? error/ssl)
  (unless (input-port? i)
    (raise-type-error who "input port" i))
  (unless (output-port? o)
    (raise-type-error who "output port" o))
  
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
                [(ssl-pump-thread) (thread (λ () (ssl-pump ssl i o clear-from-pipe-in clear-to-pipe-out close? (if connect? SSL_connect SSL_accept))))]
                [(mzssl) (mzssl ssl i o ssl-pump-thread)])
    
    
    ;TODO: need to capture when the application closes its output port
    ;we know when the input port is closed, because we eventually get an EOF on the out side
    
    (log-debug (format "SSL connection status is ~v" 
                       (pump-thread-notify ssl-pump-thread 'connect 
                                           (λ ()
                                             (error/ssl who "~a failed (input terminated prematurely)"
                                                        (if connect? "connect" "accept"))))))
    
    
    ;when the application closes its output port
    ;the pump thread must be notified of this
    
    (values (ssl-input-port mzssl (make-input-port
                                   'ssl-input-port
                                   (λ (b)
                                     clear-to-pipe-in)
                                   #f
                                   (λ ()
                                     (close-input-port clear-to-pipe-in)
                                     (thread-send ssl-pump-thread 'input-port-closed #f))))
            
            (ssl-output-port mzssl (make-output-port
                                    'ssl-output-port
                                    clear-from-pipe-out
                                    (λ (bstr start end non-block? breakable?)
                                      ((cond [non-block? write-bytes-avail*]
                                             [breakable? write-bytes-avail/enable-break]
                                             [else write-bytes-avail])
                                       bstr 
                                       clear-from-pipe-out 
                                       start 
                                       end))
                                    (λ ()
                                      (close-output-port clear-from-pipe-out)
                                      (flush-ssl ssl-pump-thread)))))))








;pumps data between the pipes, memory bios, etc...
(define (ssl-pump ssl-context ;ssl connection context this input-pump belongs to
                  cypher-port-in ;comes in from the other side of the connection
                  cypher-port-out ;goes over the wire to the other side of the connection
                  clear-port-in  ;data comes from the application over this
                  clear-port-out ;data goes out to the application over this
                  close-original? ;close down the original input and output ports when the ssl operation ends
                  connect) ;connect or accept connection
  
  (log-debug "ssl-pump started")
  
  ;we use this buffer is intermediate and stores data from the clear in port
  ;when we must do protocol negotiations
  (define read-xfer-buffer (make-immobile-bytes BUFFER-SIZE))
  
  ;this is volatile and can be used at anytime
  ;this is not preserved
  (define xfer-buffer (make-immobile-bytes BUFFER-SIZE))
  
  ;the bio that SSL_read reads from
  (define read-bio (make-mem-bio 'ssl-pump))
  
  ;the bio that SSL_write writes to
  (define write-bio (make-mem-bio 'ssl-pump))
  
  (SSL_set_bio ssl-context read-bio write-bio)
  
  (define (halt)
    (if close-original? 
        (begin
          (close-input-port cypher-port-in)
          (close-output-port cypher-port-out)
          (log-debug "pump-thread: halting; closed original ports"))
        (log-debug "pump-thread: halting; didn't close original ports"))        
    (kill-thread (current-thread)))
  
  
  ;execute the connection function
  ;it will be SSL_connect or SSL_accept
  (connect ssl-context)
  
  
  (with-handlers (((λ (exn) #t)
                  (λ (exn) (log-debug (format "ssl-pump: error -> ~a" exn)))))
  
  ;TODO: support flushing
  ;TODO: send ssl shutdown message
  ;TODO: test ssl-abandon-port
  (let main-loop ([state SSL_ERROR_NONE]  ;the last known ERROR state when calling SSL_read and SSL_write
                  [abandon-port? #f] ;tracks when the application calls ssl-abandon-port on the client port
                  [flushes empty] ;tracks any clients waiting on flushes
                  [connect-channel #f]) ;tracks the client that is waiting for a connection to complete
    
    
    (log-debug (format "ssl-pump: entering loop: clear-port-in:(~v) clear-port-out:(~v) cypher-port-in:(~v) write-bio bytes:(~v) state:(~v) ssl_state:(~v) flushes-pending:(~v) mailbox:(~v)"
                       (if (port-closed? clear-port-in)
                           "closed"
                           (if (byte-ready? clear-port-in) "ready" "not ready"))
                       (if (port-closed? clear-port-out)
                           "closed"
                           "open")
                       (if (port-closed? cypher-port-in)
                           "closed"
                           (if (byte-ready? cypher-port-in) "ready" "not ready"))
                       (BIO_ctrl_pending write-bio)
                       (SSL_ERROR->symbol state)
                       (SSL_state_string ssl-context)
                       (length flushes)
                       (mailbox->list)))
        (receive 
         
         ;exit out if something bad happened
         [(when (or (equal? state SSL_ERROR_SSL)
                    (equal? state SSL_ERROR_ZERO_RETURN)
                    (equal? state SSL_ERROR_SYSCALL)))
          (log-debug (format "ssl-pump: error ~v. exiting." state))
          (halt)]
         
         ;shutdown if both clear ports are closed
         #|[(and (port-closed? clear-port-in)
               (port-closed? clear-port-out))
          (uf|#
           
               ;when both clear-port-in and clear-port-out are closed we can halt
    ;ssl may still need to pump information (for instance a shutdown close was sent)
    ;or 
    #|(when (and (port-closed? clear-port-in)
               (port-closed? clear-port-out)
               (= (BIO_ctrl_pending write-bio) 0))
      (halt))|#
                 
         ;check the write bio for any info that must be pumped out
         ;if ssl has some encoded data that has to get written to the cypher port
         ;push it out over the wire
         [(when (> (BIO_ctrl_pending write-bio) 0))
          (let ([written (BIO_read write-bio xfer-buffer BUFFER-SIZE)])
            (write-bytes xfer-buffer cypher-port-out 0 written)
            (flush-output cypher-port-out)
            (log-debug (format "ssl-pump: wrote ~v bytes cyphertext to cypher out" written)))
          (main-loop state abandon-port? flushes connect-channel)]
         
         ;see if we can write some data out
         ;has data arrived from the application?
         ;we are using the pipe as the buffer here
         ;we peek the bytes off and try to write them
         ;if the write succeeds we commit the peeked bytes which 
         ;is equivalent to reading and then having SSL write succeed
         [(event (guard-evt (λ () (if (not (port-closed? clear-port-in)) clear-port-in never-evt))))
          (let* ([progress (port-progress-evt clear-port-in)]
                 [in-count (peek-bytes-avail! xfer-buffer 0 progress clear-port-in)])
            
            (when (equal? eof in-count)
              (close-input-port clear-port-in)
              (log-debug "ssl-pump clear-port-in closed")
              (main-loop state  
                         abandon-port?
                         flushes
                         connect-channel))
            
            (log-debug (format "read ~a bytes from clear-port-in" in-count))
            
            (let ([ssl-count (SSL_write ssl-context xfer-buffer in-count)])
              (port-commit-peeked ssl-count progress always-evt clear-port-in)
              (log-debug (format "SSL_write: wrote ~a bytes to ssl" ssl-count))
              (main-loop (if (> ssl-count 0) SSL_ERROR_NONE (SSL_get_error ssl-context ssl-count))
                         abandon-port?
                         flushes
                         connect-channel)))]
         
         
         ;any data from the cypher text port?
         ;push it into the BIO
         [(event (guard-evt (λ () (if (not (port-closed? cypher-port-in)) cypher-port-in never-evt))))
          (let ([in-count (read-bytes-avail! read-xfer-buffer cypher-port-in)])
            
            (when (equal? eof in-count)
              (close-input-port cypher-port-in)
              (log-debug "ssl-pump: cypher-port-in closed - shutting down")
              (halt))
            
            (let ([bio-count (BIO_write read-bio read-xfer-buffer in-count)])
              (unless (= in-count bio-count)
                (error 'input-pump "ssl-pump: Bio write seemed to fail!")))
            
            (log-debug (format "ssl-pump: read ~a bytes from ssl" in-count))
            
            (main-loop (let* ([bio-size (BIO_ctrl_pending read-bio)]
                              [ssl-count (SSL_read ssl-context xfer-buffer bio-size)])
                         (log-debug (format "ssl-pump: SSL_read bio-size:~v ssl-count:~v" bio-size ssl-count))
                         (if (> ssl-count 0)
                             ;write the data out and loop
                             (begin
                               (write-bytes xfer-buffer clear-port-out 0 ssl-count)
                               (flush-output clear-port-out)
                               SSL_ERROR_NONE)
                             
                             ;we failed to write data, something could have happend
                             ;that requires further action before we can read more
                             ;data
                             (SSL_get_error ssl-context ssl-count)))
                       abandon-port?
                       flushes
                       connect-channel))]
         
         ;when ssl goes SSL_OK, we can now notify the thread waiting on us to completed the connection
         ;that the connection is ok and that it can proceeed
         [(when (and connect-channel (equal? (SSL_state ssl-context) SSL_OK)))
          (log-debug "ssl-pump: sent connection ok to waiting connect")
          (async-channel-put connect-channel 'ok)
          (main-loop state abandon-port? flushes #f)]
         
         [(when (and (not (empty? flushes))
                     (or (port-closed? clear-port-in) (not (byte-ready? clear-port-in)))
                     (not (> (BIO_ctrl_pending write-bio) 0))))
          (for-each (λ (flush-channel)
                      (async-channel-put flush-channel 'ok))
                    flushes)
          (main-loop state abandon-port? empty connect-channel)]
                     
         
         ['input-port-closed
          ;since the application closed its input port, we will no longer
          ;be able to send anything to it, we can close our output port
          (close-output-port clear-port-out)
          (log-debug "ssl-pump: received message: input-port-closed")
          (main-loop state abandon-port? flushes connect-channel)]
         
         ['abandon-port
          (log-debug "ssl-pump: received message: abandon-port")
          (main-loop state #t flushes connect-channel)]
         
         [(cons 'flush flush-channel)
          (main-loop state abandon-port? (cons flush-channel flushes) connect-channel)]
         
         [(cons 'connect connect-channel)
          (log-debug "ssl-pump: receive connect message")
          (main-loop state abandon-port? flushes connect-channel)]))))


             
  
    ;TODO: send the connecting channel a failure message if the SSL_STATUS is not OK....
    #|
        (when (and connect-channel (equal? (SSL_state ssl-context) SSL_OK))
          (async-channel-put connect-channel 'SSLOK)
          (main-loop state abandon-port? flushes connect-channel))

      
      (when (and (not (empty? flushes)) 
                 (or (port-closed? (clear-port-in)) (not (byte-ready? clear-port-in))))
        (for-each (λ (flush-channel)
                    (channel-put flush-channel 'ok))
                  flushes)
        (main-loop state abandon-port? empty))|#
    
    
    
    ;if the app closes its output port, it means our clear-in will no longer receive any data
    ;so we close our clear-in port
    
    ;if the app closes its input port, it means that our clear-out will never deliver any further
    ;data so we close our clear-out port
    
    ;when clear-out and clear-in are both closed
    ;if abandon is #f
    ;we perform an SSL shutdown and then halt
    ;otherwise just halt
    
    
    
    
    ;if our cypher-in-port closes, it means the remote end closed its output port
    ;once we get want read and we have no bio bytes left to write out, we can't move forward
    ;so we should shut down
    
    ;if our cypher-out-port closes, it means the remote end closed its input port
    ;once we have bio bytes to write back out, we can make no more progress and should shut down
    
    
    
    
    ; we close our clear-in port
    
    
    
    ;then we send an SSL shutdown message, because the application is indicating that we are done
    ;it parallels how the tcp output port behaves (a tcp shutdown message is sent)
    
    ;if ssl-abandon is called, we will not send an SSL shutdown message, and will not shutdown until the applications
    ;ssl input port is closed
    
    ;if cypher-port-in closes, and we get bio bytes pending in the write bio, we will exit
    ;because there is no longer any way to communicate with the other end
    
    #|(when (and clear-port-out-closed? (not abandon-port?))
        (log-debug "ssl-pump: sending SSL_shutdown message")
        (when (zero? (SSL_shutdown ssl-context))
          (SSL_shutdown ssl-context)))|#
    
    




(define (ssl-addresses port/listener [port-numbers? #f])
  (tcp-addresses (if (ssl-listener? port/listener)
                     (ssl-listener-l port/listener)
                     (ssl-port-mzssl port/listener))
                 port-numbers?))

(define (ssl-abandon-port p)
  (error 'not-supported))
#|
    (let-values ([(mzssl input?) (lookup 'ssl-abandon-port "SSL output port" p)])
      (when input?
        (raise-type-error 'ssl-abandon-port "SSL output port" p))
      (send-pump-thread-msg 
      (let ([abandon-confirm-channel (make-channel)])
        
      (set-mzssl-shutdown-on-close?! mzssl #f)))
  |#
(define (ssl-peer-verified? p)
  (let ([ssl (mzssl-ssl (ssl-port-mzssl p))])
    (and (eq? X509_V_OK (SSL_get_verify_result ssl))
         (SSL_get_peer_certificate ssl)
         #t)))

(define (ssl-peer-subject-name p)
  (let* ([ssl (mzssl-ssl (ssl-port-mzssl p))]
         [cert (SSL_get_peer_certificate ssl)])
    (if cert
        (let ([bytes (make-bytes 1024 0)])
          (X509_NAME_oneline (X509_get_subject_name cert) bytes (bytes-length bytes)))
        #f)))

(define (ssl-peer-issuer-name p)
  (let* ([ssl (mzssl-ssl (ssl-port-mzssl p))]
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
    (ssl-listener l ctx)))

(define (ssl-close l)
  (unless (ssl-listener? l)
    (raise-type-error 'ssl-close "SSL listener" l))
  (tcp-close (ssl-listener-l l)))

;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SSL accept

(define (do-ssl-accept who tcp-accept ssl-listener)
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
      (wrap-ports who i o (ssl-listener-mzctx ssl-listener) 'accept #t #f error/network))))

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
      (wrap-ports who i o client-context-or-protocol-symbol 'connect #t #f error/network))))

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
