<?php

    // dependecy check
    if (!in_array('memcached', get_loaded_extensions())) {
        throw new Exception('Memcached extension needs to be installed.');
    }

    // load dependency
    require_once 'SSession.class.php';

    /**
     * SMSession
     *
     * Applies session security to memcached based sessions.
     * 
     * @author  Oliver Nassar <onassar@gmail.com>
     * @extends SSession
     * @example
     * <code>
     *     // instantiation
     *     require_once APP . '/vendors/PHP-SecureSessions/SMSession.class.php';
     *     $session = (new SMSession());
     *     
     *     // config
     *     $host = '.' . ($_SERVER['HTTP_HOST']);
     *     $servers = array(
     *         array('localhost', 11211)
     *     );
     *     
     *     // name, host and server setup; open session
     *     $session->setName('TSMS');
     *     $session->setHost($host);
     *     $session->addServers($servers);
     *     $session->open();
     *     $GLOBALS['SMSession'] = $session;
     * </code>
     */
    class SMSession extends SSession
    {
        /**
         * _servesr
         * 
         * (default value: array())
         * 
         * @note required; will throw exception otherwise
         * @var array
         * @access protected
         */
        protected $_servers = array();

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
            // parent setup, which sets name and session cookie parameters
            parent::_setup();

            // servers not specified; fail
            if (empty($this->_servers)) {
                throw new Exception('Memcached server(s) not set.');
            }

            // format servers for connection
            $parsed = array();
            foreach ($this->_servers as $server) {
                $formatted = implode(':', $server);
                array_push($parsed, $formatted);
            }

            // set handler
            ini_set('session.save_handler', 'memcached');
            ini_set('session.save_path', implode(', ', $parsed));
        }

        /**
         * addServer function.
         * 
         * @access public
         * @param array $server
         * @return void
         */
        public function addServer(array $server)
        {
            // check if session already opened
            if ($this->_open === true) {
                throw new Exception(
                    'SMSession Error: Cannot add server after session opened.'
                );
            }

            // push into local stack
            array_push($this->_servers, $server);
        }

        /**
         * addServers function.
         * 
         * @access public
         * @param array $servers
         * @return void
         */
        public function addServers(array $servers)
        {
            foreach ($servers as $server) {
                $this->addServer($server);
            }
        }
    }
