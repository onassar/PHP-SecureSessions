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
         * _expiry
         * 
         * (default value: 0)
         * 
         * @access  protected
         * @var     int
         */
        protected $_expiry = 0;

        /**
         * _host
         *  
         * @note    default value will be pulled from <_SERVER>
         * @access  protected
         * @var     string
         */
        protected $_host;

        /**
         * _httponly
         *  
         * (default value: true)
         * 
         * @access  protected
         * @var     bool
         */
        protected $_httponly = true;

        /**
         * _lifetime
         *  
         * (default value: 900)
         * 
         * @access  protected
         * @var     int
         */
        protected $_lifetime = 900;

        /**
         * _name
         *  
         * (default value: 'SN')
         * 
         * @access  protected
         * @var     string
         */
        protected $_name = 'SN';

        /**
         * _open
         *  
         * (default value: false)
         * 
         * @access  protected
         * @var     bool
         */
        protected $_open = false;

        /**
         * _path
         * 
         * (default value: '/')
         * 
         * @access  protected
         * @var     string
         */
        protected $_path = '/';

        /**
         * _secret
         * 
         * Secret used for generating the signature. Is used in conjunction with
         * the <stamp> method for securing sessions.
         * 
         * (default value: 'jkn*#j34!')
         * 
         * @access  protected
         * @var     string
         */
        protected $_secret = 'jkn*#j34!';

        /**
         * _secure
         *  
         * (default value: false)
         * 
         * @access  protected
         * @var     bool
         */
        protected $_secure = false;

        /**
         * _secureWithIPAddress
         *  
         * (default value: false)
         * 
         * @access  protected
         * @var     bool
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
            $this->setHost('.' . ($_SERVER['HTTP_HOST']));
        }

        /**
         * _invalid
         * 
         * @note    decoupled from <open> method to allow for logging by child
         *          classes
         * @access  protected
         * @return  void
         */
        protected function _invalid(): void
        {
            // reset session
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
        protected function _ip()
        {
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) === true) {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            }
            if (isset($_SERVER['REMOTE_ADDR']) === true) {
                return $_SERVER['REMOTE_ADDR'];
            }
            return '(unknown)';
        }

        /**
         * _setup
         * 
         * @access  protected
         * @return  void
         */
        protected function _setup(): void
        {
            ini_set('session.name', $this->_name);
            ini_set('session.gc_maxlifetime', $this->_lifetime);
            session_set_cookie_params(
                $this->_expiry,
                $this->_path,
                $this->_host,
                $this->_secure,
                $this->_httponly
            );
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
        protected function _sign($sid)
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
            $agent = isset($_SERVER['HTTP_USER_AGENT']) === true ? $_SERVER['HTTP_USER_AGENT'] : '(unknown)';
            if ($this->_secureWithIPAddress === true) {
                return $agent . $this->_ip();
            }
            return $agent;
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
        protected function _valid($sid, $signature)
        {
            // return regenerated vs passed in
            $regenerated = $this->_sign($sid);
            return $signature === $regenerated;
        }

        /**
         * destroy
         * 
         * @access  public
         * @return  void
         */
        public function destroy(): void
        {
            // empty
            $_SESSION = array();

            // clear cookies from agent
            $signature = ($this->_name) . 'Signature';
            $path = $this->_path;
            $path = ($path) . '; samesite=none';
            setcookie(
                $this->_name,
                '',
                time() - 42000,
                $path,
                $this->_host,
                $this->_secure,
                $this->_httponly
            );
            setcookie(
                $signature,
                '',
                time() - 42000,
                $path,
                $this->_host,
                $this->_secure,
                $this->_httponly
            );

            /**
             * Clear out of global scope, since setcookie requires buffer flush
             * to update global <_COOKIE> array.
             */
            unset($_COOKIE[$this->_name]);
            unset($_COOKIE[$signature]);

            // destroy
            session_destroy();
        }

        /**
         * open
         * 
         * @access  public
         * @return  void
         */
        public function open(): void
        {
            // setup session
            $this->_setup();

            // open up session
            session_start();
            $sid = session_id();

            // mark that a session has been opened
            $this->_open = true;

            // signature check
            $key = ($this->_name) . 'Signature';
            if (isset($_COOKIE[$key]) === true) {

                // if session id is invalid
                $signature = $_COOKIE[$key];
                $valid = $this->_valid($sid, $signature);
                if ($valid === false) {

                    // invalid session processing
                    $this->_invalid();
                }
            }
            // session not yet opened
            else {

                // create signature-cookie
                $signature = $this->_sign($sid);
                $path = $this->_path;
                $path = ($path) . '; samesite=none';
                setcookie(
                    $key,
                    $signature,
                    $this->_expiry,
                    $path,
                    $this->_host,
                    $this->_secure,
                    $this->_httponly
                );
            }
        }

        /**
         * setExpiry
         * 
         * @access  public
         * @param   int $seconds
         * @return  void
         */
        public function setExpiry($seconds): void
        {
            $this->_expiry = $seconds;
        }

        /**
         * setHost
         * 
         * @access  public
         * @param   string $host
         * @return  void
         */
        public function setHost($host): void
        {
            $this->_host = $host;
        }

        /**
         * setLifetime
         * 
         * @access  public
         * @param   string $lifetime
         * @return  void
         */
        public function setLifetime($lifetime): void
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
        public function setName($name): void
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
        public function setPath($path): void
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
        public function setSecret($secret): void
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
