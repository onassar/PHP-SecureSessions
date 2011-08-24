<?php

    /**
     * SSession class. Secure session class.
     * 
     * @note includes <REMOTE_ADDR> restriction in the session id signing
     * @note includes <HTTP_USER_AGENT> restriction in the session id signing
     */
    class SSession
    {
        /**
         * _host
         * 
         * @note optional; default value will be pulled from $_SERVER
         * @var string
         * @access protected
         */
        protected $_host;

        /**
         * _expiry
         * 
         * @var int
         * @access protected
         */
        protected $_expiry = 0;

        /**
         * _httponly
         * 
         * (default value: false)
         * 
         * @var bool
         * @access protected
         */
        protected $_httponly = false;

        /**
         * _name
         * 
         * (default value: 'SN')
         * 
         * @note optional
         * @var string
         * @access protected
         */
        protected $_name = 'SN';

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
         * _secret. Secret used for generation the signature. Is used in
         *     conjunction with the <REMOTE_ADDR> and <HTTP_USER_AGENT> values
         * 
         * (default value: 'jkn*#j34!')
         * 
         * @var string
         * @access protected
         */
        protected $_secret = 'jkn*#j34!';

        /**
         * _secure
         * 
         * (default value: false)
         * 
         * @var bool
         * @access protected
         */
        protected $_secure = false;

        /**
         * _seperator
         * 
         * (default value: '---')
         * 
         * @note optional
         * @var string
         * @access protected
         */
        protected $_seperator = '---';

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
         * _getSid function. Returns the actual sid (as it relates to the
         *    data-store) based on the cookie passed in (which is signed).
         * 
         * @access protected
         * @param string $cookie
         * @return false|string
         */
        protected function _getSid($cookie)
        {
            // grab pieces; bail if invalid format already
            $pieces = explode($this->_seperator, $cookie);
            if (count($pieces) !== 2) {
                return false;
            }
            return $pieces[0];
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
         * _sign function. Generates signature by appending the session id with
         *     a signature genatered from the id, user agent, user IP and a
         *     secret. This signature is hashed and seperated before being
         *     returned.
         * 
         * @access protected
         * @param string $sid
         * @return string
         */
        protected function _sign($sid)
        {
            $agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
            $secret = $agent . $ip . $this->_secret;
            $signature = hash('sha256', $sid . $secret);
            return $sid . $this->_seperator . $signature;
        }

        /**
         * _validSession function. Checks whether the session is valid (eg.
         *     hasn't been tampered with) by regenerating the signature and
         *     comparing it to what was passed.
         * 
         * @access protected
         * @param string $sid
         * @param string $signature
         * @return boolean
         */
        protected function _validSession($sid, $signature)
        {
            // return regenerated vs passed in
            $regenerated = $this->_sign($sid);
            return $signature === $regenerated;
        }

        public function destroy()
        {
            // empty
            $_SESSION = array();

            // clear cookies from agent
            $signature = ($this->_name) . '-signature';
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
             *     to update global cookie array.
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
            session_start();
            $sid = session_id();

            // signature check
            $key = ($this->_name) . '-signature';
            if (isset($_COOKIE[$key])) {

                // if session id is invalid
                $signature = $_COOKIE[$key];
                $valid = $this->_validSession($sid, $signature);
                if ($valid === false) {

                    // reset session
                    $this->destroy();
                    $this->open();
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

        /**
         * setSeperator function.
         * 
         * @access public
         * @param string $seperator
         * @return void
         */
        public function setSeperator($seperator)
        {
            $this->_seperator = $seperator;
        }
    }

?>
