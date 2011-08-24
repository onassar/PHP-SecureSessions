<?php

    // dependecy check
    if (!in_array('memcached', get_loaded_extensions())) {
        throw new Exception('Memcached extension needs to be installed.');
    }

    // load dependency
    require_once 'SSession.class.php';

    /**
     * SMSession class. Extension of secure-session class that provides secured
     *     memcached-based sessions.
     * 
     * @extends SSession
     */
    class SMSession extends SSession
    {
        /**
         * _server
         * 
         * (default value: array())
         * 
         * @note required; will throw exception otherwise
         * @var array
         * @access protected
         */
        protected $_server = array();

        /**
         * __construct function.
         * 
         * @access public
         * @return void
         */
        public function __construct()
        {
            parent::__construct();
        }

        /**
         * _setup function.
         * 
         * @access protected
         * @return void
         */
        protected function _setup()
        {
            parent::_setup();
            if (empty($this->_server)) {
                throw new Exception('Memcached server not set.');
            }
            ini_set('session.save_handler', 'memcached');
            ini_set('session.save_path', ($this->_server['host']) . ':' . ($this->_server['port']));
        }

        /**
         * setServer function.
         * 
         * @access public
         * @param array $server
         * @return void
         */
        public function setServer(array $server)
        {
            $this->_server = $server;
        }
    }

?>
