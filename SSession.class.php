<?php

    /**
     * SSession
     * 
     * Secure session class.
     * 
     * @author Oliver Nassar <onassar@gmail.com>
     * @notes  includes session hijacking prevention by bounding sessions to ip
     *         addresses and user agents
     */
    class SSession
    {
        /**
         * _expiry.
         * 
         * @var int
         * @access protected
         */
        protected $_expiry = 0;

        /**
         * _host.
         * 
         * @note default value will be pulled from $_SERVER
         * @var string
         * @access protected
         */
        protected $_host;

        /**
         * _httponly.
         * 
         * (default value: true)
         * 
         * @var bool
         * @access protected
         */
        protected $_httponly = true;

        /**
         * _name.
         * 
         * (default value: 'SN')
         * 
         * @var string
         * @access protected
         */
        protected $_name = 'SN';

        /**
         * _open.
         * 
         * (default value: false)
         * 
         * @var bool
         * @access protected
         */
        protected $_open = false;

        /**
         * _path
         * 
         * (default value: '/')
         * 
         * @var string
         * @access protected
         */
        protected $_path = '/';

        /**
         * _secret. Secret used for generating the signature. Is used in
         *     conjunction with the <stamp> method for securing sessions.
         * 
         * (default value: 'jkn*#j34!')
         * 
         * @var string
         * @access protected
         */
        protected $_secret = 'jkn*#j34!';

        /**
         * _secure.
         * 
         * (default value: false)
         * 
         * @var bool
         * @access protected
         */
        protected $_secure = false;

        /**
         * __construct function.
         * 
         * @access public
         * @return void
         */
        public function __construct()
        {
            $this->setHost('.' . ($_SERVER['HTTP_HOST']));
        }

        /**
         * _invalid function.
         * 
         * @note decoupled from <open> method to allow for logging by child
         *     classes
         * @access protected
         * @return void
         */
        public function _invalid()
        {
            // reset session
            $this->destroy();
            $this->open();
        }

        /**
         * _ip function. Returns the client's IP address, either directly, or
         *     whichever was forwarded by the detected load balancer.
         * 
         * @access protected
         * @return string
         */
        protected function _ip()
        {
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            }
            if (isset($_SERVER['REMOTE_ADDR'])) {
                return $_SERVER['REMOTE_ADDR'];
            }
            return '(unknown)';
        }

        /**
         * _setup function.
         * 
         * @access protected
         * @return void
         */
        protected function _setup()
        {
            ini_set('session.name', $this->_name);
            session_set_cookie_params(
                $this->_expiry,
                $this->_path,
                $this->_host,
                $this->_secure,
                $this->_httponly
            );
        }

        /**
         * _sign function. Generates a signature by appending the <stamp> method
         *     response with the a secret. This signature is hashed before being
         *     returned.
         * 
         * @access protected
         * @param string $sid
         * @return string
         */
        protected function _sign($sid)
        {
            $stamp = $this->_stamp() . $this->_secret;
            $signature = hash('sha256', $sid . $stamp);
            return $signature;
        }

        /**
         * _stamp function. Returns a stamp to aid in securing a server, by
         *     concatenating the user agent and IP of the client.
         * 
         * @note decoupled from <_sign> to allow for customizing the stamp
         * @access protected
         * @return string
         */
        protected function _stamp()
        {
            $agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            return $agent . $this->_ip();
        }

        /**
         * _valid function. Checks whether the session is valid (eg.
         *     hasn't been tampered with) by regenerating the signature and
         *     comparing it to what was passed.
         * 
         * @access protected
         * @param string $sid
         * @param string $signature
         * @return boolean
         */
        protected function _valid($sid, $signature)
        {
            // return regenerated vs passed in
            $regenerated = $this->_sign($sid);
            return $signature === $regenerated;
        }

        /**
         * destroy function.
         * 
         * @access public
         * @return void
         */
        public function destroy()
        {
            // empty
            $_SESSION = array();

            // clear cookies from agent
            $signature = ($this->_name) . 'Signature';
            setcookie(
                $this->_name,
                '',
                time() - 42000,
                $this->_path,
                $this->_host,
                $this->_secure,
                $this->_httponly
            );
            setcookie(
                $signature,
                '',
                time() - 42000,
                $this->_path,
                $this->_host,
                $this->_secure,
                $this->_httponly
            );

            /**
             * Clear out of global scope, since setcookie requires buffer flush
             *     to update global <_COOKIE> array.
             */
            unset($_COOKIE[$this->_name]);
            unset($_COOKIE[$signature]);

            // destroy
            session_destroy();
        }

        /**
         * open function.
         * 
         * @access public
         * @return void
         */
        public function open()
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
            if (isset($_COOKIE[$key])) {

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
                setcookie(
                    $key,
                    $signature,
                    $this->_expiry,
                    $this->_path,
                    $this->_host,
                    $this->_secure,
                    $this->_httponly
                );
            }
        }

        /**
         * setExpiry function.
         * 
         * @access public
         * @param int $seconds
         * @return void
         */
        public function setExpiry($seconds)
        {
            $this->_expiry = $seconds;
        }

        /**
         * setHost function.
         * 
         * @access public
         * @param string $host
         * @return void
         */
        public function setHost($host)
        {
            $this->_host = $host;
        }

        /**
         * setName function. Sets the name of the session (cookie-wise)
         * 
         * @access public
         * @param string $name
         * @return void
         */
        public function setName($name)
        {
            $this->_name = $name;
        }

        /**
         * setPath function.
         * 
         * @access public
         * @param string $path
         * @return void
         */
        public function setPath($path)
        {
            $this->_path = $path;
        }

        /**
         * setSecret function. Secret used for the hashing/signature process.
         * 
         * @access public
         * @param string $secret
         * @return void
         */
        public function setSecret($secret)
        {
            $this->_secret = $secret;
        }

        /**
         * setSecured function.
         * 
         * @access public
         * @return void
         */
        public function setSecured()
        {
            $this->_secure = true;
        }
    }
