PHP Secure Sessions
===

PHP-SecureSessions is a collection of two classes that facilitate session
manipulation, in a, you guessed it, secure way.

### Secure Sessions
A _SSession_ instance facilitates the opening of a secure session, with the
following features:

 - Key securing through secondary cookie
 - Key securing through user agent (browser) binding
 - Key securing through remote address (IP address) binding

The manipulation of sessions remains unchanged. Writing/reading to/from them is
done in the same way as always

### Secure Memcached Sessions
The second class acts as a child, and provides the same functionality and
security. Added functionality includes the addition of *memcached* server
addresses.