PHP Secure Sessions
===

PHP-SecureSessions is a collection of two classes that facilitate session
manipulation, in a, you guessed it, secure way.

### Secure Sessions
A **SSession** instance facilitates the opening of a secure session, with the
following features:

 - Key securing through secondary cookie
 - Key securing through user agent (browser) binding
 - Key securing through remote address (IP address) binding

The manipulation of sessions remains unchanged. Writing/reading to/from them is
done in the same way as always.

### Secure Memcached Sessions
The second class acts as a child, and provides the same security. Added
functionality includes the addition of *memcached* server addresses.

### Sample Secured Memcached Session (*SMSession*) Instantiation

``` php
// instantiation
require_once APP . '/vendors/PHP-SecureSessions/SMSession.class.php';
$session = new SMSession();

// config
$host = '.' . ($_SERVER['HTTP_HOST']);
$servers = array(
    array('localhost', 11211)
);

// name, host and server setup; open session
$session->setName('TSMS');
$session->setHost($host);
$session->addServers($servers);
$session->open();
$GLOBALS['SMSession'] = $session;
```

### Security Note
Here are a few caveats on the security process of this library.

The reason for the second-cookie is to have it encompass the <user_agent> and
<remote_addr> of the browsing user, coupled with a salt. This allows a check
being made against these properties for the session to be coupled into a cookie
rather than a session variable.

In theory, a session could be opened, and the remote address and user agent be
stored through the standard `$_SESSION['browser'] = $_SERVER['HTTP_USER_AGENT']`
along with the IP address, and then do a check against these.

I decided to use the cookie approach to keep the session data clean and
unaffected by this library.

The appropriate server-side data is still used in the validation (see the
`_sign` and `_stamp` methods) process, but keeps it all a little more clear-cut.

Additionally, this process is intrinsically faulty if your data is being
sniffed. If someone has access to all your cookies, they could in theory
replicate them on their machine, view your IP and user agent (and spoof them
accordingly), and gain your session-identity.

The security presented here is meant as a prevention to the most basic hijacking
attempts (whereby your session id, or sid, is uncovered and spoofed).

For true security, you should definately have *all* your traffic trafficked
through SSL. This includes all your image, asset, and application requests.

If you are able to do this, ensure that you use the `setSecured` method upon
instantiating a session.

### Resources
See [Living with HTTPS](http://www.imperialviolet.org/2012/07/19/hope9talk.html)
for more information on
[HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security), and how to
implement a certificate in the best way.

Check out [StartSSL](https://www.startssl.com/) for a free low-assurance
certificate. Don't let the word *low* throw you off. It's a certificate that
will encrypt your data between machines.
