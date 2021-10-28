<?php

    /**
     * SSession
     * 
     * Secure session class.
     * 
     * @author  Oliver Nassar <onassar@gmail.com>
     * @note    includes session hijacking prevention by bounding sessions to ip
     *          addresses and user agents
     */
    class SSession
    {
        /**
         * _expires
         * 
         * @access  protected
         * @var     int (default: 0)
         */
        protected $_expires = 0;

        /**
         * _host
         *  
         * @access  protected
         * @var     null|string (default: null)
         */
        protected $_host = null;

        /**
         * _httponly
         * 
         * @access  protected
         * @var     bool (default: true)
         */
        protected $_httponly = true;

        /**
         * _lifetime
         * 
         * @access  protected
         * @var     int (default: 900)
         */
        protected $_lifetime = 900;

        /**
         * _name
         * 
         * @access  protected
         * @var     string (default: 'SN')
         */
        protected $_name = 'SN';

        /**
         * _open
         * 
         * @access  protected
         * @var     bool (default: false)
         */
        protected $_open = false;

        /**
         * _path
         * 
         * @access  protected
         * @var     string (default: '/')
         */
        protected $_path = '/';

        /**
         * _secret
         * 
         * Secret used for generating the signature. Is used in conjunction with
         * the <stamp> method for securing sessions.
         * 
         * @access  protected
         * @var     string (default: 'jkn*#j34!')
         */
        protected $_secret = 'jkn*#j34!';

        /**
         * _secure
         * 
         * @access  protected
         * @var     bool (default: false)
         */
        protected $_secure = false;

        /**
         * _secureWithIPAddress
         * 
         * @access  protected
         * @var     bool (default: false)
         */
        protected $_secureWithIPAddress = false;

        /**
         * __construct
         * 
         * @access  public
         * @return  void
         */
        public function __construct()
        {
            $host = '.' . ($_SERVER['HTTP_HOST']);
            $this->setHost($host);
        }

        /**
         * _deleteCookie
         * 
         * @access  protected
         * @param   string $name
         * @return  bool
         */
        protected function _deleteCookie(string $name): bool
        {
            $value = '';
            $expires = time() - 86400;
            $path = $this->_path;
            $domain = $this->_host;
            $secure = $this->_secure;
            $httponly = $this->_httponly;
            $options = compact('expires', 'path', 'domain', 'secure', 'httponly');
            $response = $this->_setCookie($name, $value, $options);
            return $response;
        }

        /**
         * _getSessionCookieParamsArgs
         * 
         * @access  protected
         * @return  array
         */
        protected function _getSessionCookieParamsArgs(): array
        {
            $lifetime = $this->_lifetime;
            $path = $this->_path;
            $domain = $this->_host;
            $secure = $this->_secure;
            $httponly = $this->_httponly;
            if (version_compare(PHP_VERSION, '7.3.0', '>=') === true) {
                $samesite = 'None';
                $options = compact('lifetime', 'path', 'domain', 'secure', 'httponly', 'samesite');
                $args = array($options);
                return $args;
            }
            $path = ($path) . '; samesite=none';
            $args = array($lifetime, $path, $domain, $secure, $httponly);;
            return $args;
        }

        /**
         * _invalidate
         * 
         * @note    decoupled from <open> method to allow for logging by child
         *          classes
         * @access  protected
         * @return  void
         */
        protected function _invalidate(): void
        {
            $this->destroy();
            $this->open();
        }

        /**
         * _ip
         * 
         * Returns the client's IP address, either directly, or whichever was
         * forwarded by the detected load balancer.
         * 
         * @access  protected
         * @return  string
         */
        protected function _ip(): string
        {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '(unknown)';
            return $ip;
        }

        /**
         * _setCookie
         * 
         * @access  public
         * @param   string $name
         * @param   mixed $value
         * @param   array $options
         * @return  bool
         */
        public function _setCookie(string $name, $value, array $options): bool
        {
            if (version_compare(PHP_VERSION, '7.3.0', '>=') === true) {
                $options['samesite'] = 'None';
                setcookie($name, $value, $options);
                return true;
            }
            $expires = $options['expires'];
            $path = $options['path'];
            $path = ($path) . '; samesite=none';
            $domain = $options['domain'];
            $secure = $options['secure'];
            $httponly = $options['httponly'];
            $args = array($name, $value, $expires, $domain, $secure, $httponly);
            setcookie(... $args);
            return true;
        }

        /**
         * _setup
         * 
         * @see     https://www.php.net/manual/en/function.session-set-cookie-params.php
         * @see     https://www.php.net/manual/en/function.setcookie.php
         * @see     https://stackoverflow.com/questions/39750906/php-setcookie-samesite-strict
         * @access  protected
         * @return  void
         */
        protected function _setup(): void
        {
            // Runetime settings
            $name = $this->_name;
            $lifetime = $this->_lifetime;
            ini_set('session.name', $name);
            ini_set('session.gc_maxlifetime', $lifetime);

            // Cookie params
            $args = $this->_getSessionCookieParamsArgs();
            session_set_cookie_params(... $args);
        }

        /**
         * _sign
         * 
         * Generates a signature by appending the <stamp> method response with
         * the a secret. This signature is hashed before being returned.
         * 
         * @access  protected
         * @param   string $sid
         * @return  string
         */
        protected function _sign(string $sid): string
        {
            $stamp = $this->_stamp() . $this->_secret;
            $signature = hash('sha256', $sid . $stamp);
            return $signature;
        }

        /**
         * _stamp
         * 
         * Returns a stamp to aid in securing a server, by concatenating the
         * user agent and IP of the client.
         * 
         * @note    decoupled from <_sign> to allow for customizing the stamp
         * @access  protected
         * @return  string
         */
        protected function _stamp()
        {
            $agent = $_SERVER['HTTP_USER_AGENT'] ?? '(unknown)';
            $stamp = $agent;
            if ($this->_secureWithIPAddress === false) {
                return $stamp;
            }
            $ip = $this->_ip();
            $stamp = ($agent) . ($ip);
            return $stamp;
        }

        /**
         * _valid
         * 
         * Checks whether the session is valid (eg. hasn't been tampered with)
         * by regenerating the signature and comparing it to what was passed.
         * 
         * @access  protected
         * @param   string $sid
         * @param   string $signature
         * @return  bool
         */
        protected function _valid(string $sid, string $signature): bool
        {
            // return regenerated vs passed in
            $regenerated = $this->_sign($sid);
            $valid = $signature === $regenerated;
            return $valid;
        }

        /**
         * destroy
         * 
         * @see     https://www.php.net/manual/en/function.setcookie.php
         * @see     https://stackoverflow.com/questions/39750906/php-setcookie-samesite-strict
         * @access  public
         * @return  void
         */
        public function destroy(): void
        {
            // Clear server side session data
            $_SESSION = array();

            // Delete cookies
            $sessionCookieName = $this->_name;
            $signatureCookieName = ($sessionCookieName) . 'Signature';
            $this->_deleteCookie($sessionCookieName);
            $this->_deleteCookie($signatureCookieName);

            // Clear cookies from global namespace
            unset($_COOKIE[$sessionCookieName]);
            unset($_COOKIE[$signatureCookieName]);

            // Formally destroy things
            session_destroy();
        }

        /**
         * open
         * 
         * @see     https://www.php.net/manual/en/function.setcookie.php
         * @see     https://stackoverflow.com/questions/39750906/php-setcookie-samesite-strict
         * @access  public
         * @return  bool
         */
        public function open(): bool
        {
            // Prepare runtime and cookie settings
            $this->_setup();

            // Open the session on the server
            session_start();
            $sid = session_id();
            $this->_open = true;

            // Deal with existing session
            $signatureCookieName = ($this->_name) . 'Signature';
            $signatureCookieValue = $_COOKIE[$signatureCookieName] ?? null;
            if ($signatureCookieValue !== null) {
                $valid = $this->_valid($sid, $signatureCookieValue);
                if ($valid === false) {
                    $this->_invalidate();
                }
                return true;
            }            

            // Set the cookie
            $value = $this->_sign($sid);
            $expires = $this->_expires;
            $path = $this->_path;
            $domain = $this->_host;
            $secure = $this->_secure;
            $httponly = $this->_httponly;
            $options = compact('expires', 'path', 'domain', 'secure', 'httponly');
            $this->_setCookie($signatureCookieName, $value, $options);
            return true;
        }

        /**
         * setExpiry
         * 
         * @access  public
         * @param   int $seconds
         * @return  void
         */
        public function setExpiry(int $seconds): void
        {
            $this->_expires = $seconds;
        }

        /**
         * setHost
         * 
         * @access  public
         * @param   string $host
         * @return  void
         */
        public function setHost(string $host): void
        {
            $this->_host = $host;
        }

        /**
         * setLifetime
         * 
         * @access  public
         * @param   int $lifetime
         * @return  void
         */
        public function setLifetime(int $lifetime): void
        {
            $this->_lifetime = $lifetime;
        }

        /**
         * setName
         * 
         * Sets the name of the session (cookie-wise).
         * 
         * @access  public
         * @param   string $name
         * @return  void
         */
        public function setName(string $name): void
        {
            $this->_name = $name;
        }

        /**
         * setPath
         * 
         * @access  public
         * @param   string $path
         * @return  void
         */
        public function setPath(string $path): void
        {
            $this->_path = $path;
        }

        /**
         * setSecret
         * 
         * Secret used for the hashing/signature process.
         * 
         * @access  public
         * @param   string $secret
         * @return  void
         */
        public function setSecret(string $secret): void
        {
            $this->_secret = $secret;
        }

        /**
         * setSecured
         * 
         * @access  public
         * @return  void
         */
        public function setSecured(): void
        {
            $this->_secure = true;
        }
    }
