#lang racket/base

(require net/url
         racket/port)


(port->string (get-pure-port (string->url "https://localhost/foo")))


