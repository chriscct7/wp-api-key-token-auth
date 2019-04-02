<?php
/**
 * Plugin Name:       Rest Token Authentication for WP-API
 * Plugin URI:        https://www.chriscct7.com
 * Description:       Extends the WP REST API using Tokens Authentication as an authentication method.
 * Version:           1.0.0
 * Author:            Chris Christoff
 * Author URI:        http://www.chriscct7.com
 * License:           GPLv2 or later
 *
 * Rest Token Authentication for WP-API is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 *
 * Rest Token Authentication for WP-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rest Token Authentication for WP-API. If not, see <http://www.gnu.org/licenses/>.
 */

// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
    die;
}

function run_token_auth() {
    $plugin = new Token_Auth();
}
run_token_auth();

/**
 * Processes all actions sent via POST and GET by looking for the 'rest-api-token-auth-action'
 * request and running do_action() to call the function
 *
 * @since 1.0.0
 * @return void
 */
function rest_api_token_auth_process_actions() {
    if ( isset( $_POST['rest-api-token-auth-action'] ) ) {
        do_action( 'rest_api_token_auth_' . $_POST['rest-api-action'], $_POST );
    }

    if ( isset( $_GET['rest-api-token-auth-action'] ) ) {
        do_action( 'rest_api_token_auth_' . $_GET['rest-api-action'], $_GET );
    }
}
add_action( 'admin_init', 'rest_api_token_auth_process_actions' );

/**
 * The core plugin class.
 *
 * This is all the code involved to make the plugin work
 *
 * @since      1.0.0
 *
 * @author     Chris Christoff <hello@chriscct7.com>
 */
class Token_Auth {
    /**
     * The route for the api calls to follow
     *
     * @since    1.0.0
     *
     * @var string Route for the api calls to follow
     */
    private $route = 'auth';

    /**
     * The version of this api.
     *
     * @since    1.0.0
     *
     * @var string The current version of this api.
     */
    private $version = '1';

    /**
     * The namespace to add to the api calls.
     *
     * @var string The namespace to add to the api call
     */
    private $namespace;

    /**
     * Store errors to display if the Token is wrong
     *
     * @var WP_Error
     */
    private $token_error = null;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     */

    /**
     * Define the core functionality of the plugin.
     *
     * Set the plugin name and the plugin version that can be used throughout the plugin.
     * Load the dependencies, define the locale, and set the hooks for the admin area and
     * the public-facing side of the site.
     *
     * @since    1.0.0
     */
    public function __construct( $route = 'auth', $version = '1' ) {
        $this->route       = $route;
        $this->version     = $version;
        $this->namespace   = $this->route . '/v' . intval( $this->version ); 
        $this->define_public_hooks();     
    }

    /**
     * Register all of the hooks related to the public-facing functionality
     * of the plugin.
     *
     * @since    1.0.0
     */
    private function define_public_hooks() {
        // REST API
        add_action( 'rest_api_init',                            array( $this, 'add_api_routes' ) );
        add_filter( 'rest_api_init',                            array( $this, 'add_cors_support' ) );
        //add_filter( 'determine_current_user',                 array( $this, 'determine_current_user' ), 99 ); 
        add_filter( 'rest_pre_dispatch',                        array( $this, 'rest_pre_dispatch' ), 10, 2 );
        
        // Admin Area
        if ( is_admin() && ( !defined( 'DOING_AJAX' ) || !DOING_AJAX ) ) {
            // load admin keys table
            require_once 'class-api-keys-table.php';

            // load admin actions
            add_action( 'show_user_profile',                    array( $this, 'user_key_field'   ) );
            add_action( 'edit_user_profile',                    array( $this, 'user_key_field'   ) );
            add_action( 'personal_options_update',              array( $this, 'update_key'       ) );
            add_action( 'edit_user_profile_update',             array( $this, 'update_key'       ) );
            add_action( 'rest_api_token_auth_process_api_key',  array( $this, 'process_api_key'  ) );
        }  
    }

    /**
     * Add the endpoints to the API
     */
    public function add_api_routes() {
        register_rest_route( $this->namespace, 'token/', array(
            'methods' => 'POST',
            'callback' => array( $this, 'retrieve_token' ),
        ) );

        register_rest_route( $this->namespace, 'token/generate', array(
            'methods' => 'POST',
            'callback' => array( $this, 'generate_token' ),
        ) );

        register_rest_route( $this->namespace, 'token/validate', array(
            'methods' => 'POST',
            'callback' => array( $this, 'validate_token' ),
        ) );

        register_rest_route( $this->namespace, 'token/retrieve', array(
            'methods' => 'POST',
            'callback' => array( $this, 'retrieve_token' ),
        ) );

        register_rest_route( $this->namespace, 'token/revoke', array(
            'methods' => 'POST',
            'callback' => array( $this, 'revoke_token' ),
        ) );

        register_rest_route( $this->namespace, 'token/regenerate', array(
            'methods' => 'POST',
            'callback' => array( $this, 'regenerate_token' ),
        ) );
    }

    /**
     * Add CORs suppot to the request.
     */
    public function add_cors_support() {
        // we're allowing CORS by default. If you want to turn it off, define TOKEN_AUTH_CORS_ENABLE as false in wp-config.php
        $enable_cors = defined( 'TOKEN_AUTH_CORS_ENABLE' ) ? TOKEN_AUTH_CORS_ENABLE : true;
        if ($enable_cors) {
            $headers = apply_filters( 'token_auth_cors_allow_headers', 'Access-Control-Allow-Headers, Content-Type, Authorization' );
            header( sprintf( 'Access-Control-Allow-Headers: %s', $headers ) );
        }
    }
    // todo: docbloc
    /**
     * Get the user and password in the request body and retrieve their token and public key
     *
     * @param [type] $request [description]
     *
     * @return [type] [description]
     */
    public function retrieve_token( $request ) {
        $username = $request->get_param( 'username' );
        $password = $request->get_param( 'password' );

        /**
         * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
         * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
         * recursion and a stack overflow unless the current function is removed from the determine_current_user
         * filter during authentication.
         */
        remove_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 20 );

        /** Try to authenticate the user with the passed credentials*/
        $user = wp_authenticate( $username, $password );

        add_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 20 );

        /** If the authentication fails return a error*/
        if ( is_wp_error ($user ) ) {
            return new WP_Error(
                'token_auth_failed',
                __('Invalid Credentials.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Valid credentials, the user exists attempt to retrive their public key */
        $public_key         = $this->get_user_public_key( $user->ID );

        if ( empty( $public_key ) ) {
            return new WP_Error(
                'token_auth_need_to_generate',
                __('No keys set up for user. Run generate.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        $token              = $this->get_token( $user->ID );
        $data               = array();
        $data['token']      = $token;
        $data['public_key'] = $public_key;
        

        /** Let the user modify the data before send it back */
        // todo: docbloc
        $data = apply_filters( 'token_auth_token_before_dispatch_retrieve', $data, $user );
        return json_encode( $data );
    }

    // todo: docbloc
    /**
     * Get the user and password in the request body and generate keys and token
     *
     * @param [type] $request [description]
     *
     * @return [type] [description]
     */
    public function generate_token( $request ) {
        $username = $request->get_param( 'username' );
        $password = $request->get_param( 'password' );

        /**
         * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
         * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
         * recursion and a stack overflow unless the current function is removed from the determine_current_user
         * filter during authentication.
         */
        remove_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 20 );

        /** Try to authenticate the user with the passed credentials*/
        $user = wp_authenticate( $username, $password );

        add_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 20 );

        /** If the authentication fails return a error*/
        if ( is_wp_error( $user ) ) {
            return new WP_Error(
                'token_auth_failed',
                __('Invalid Credentials.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Valid credentials, the user exists attempt to create the according keys */
        $public_key = $this->get_user_public_key( $user->ID );
        $secret_key = $this->get_user_secret_key( $user->ID );

        if ( empty( $public_key ) ) {
            $new_public_key = $this->generate_public_key( $user->user_email );
            $new_secret_key = $this->generate_private_key( $user->ID );
        } else {
            return new WP_Error(
                'token_auth_keys_exist',
                __('Keys already exist. Retrieve them.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        update_user_meta( $user->ID, 'rest_api_token_auth_public_key', $new_public_key );
        update_user_meta( $user->ID, 'rest_api_token_auth_secret_key', $new_secret_key );        
    
        $token              = $this->get_token( $user->ID );

        $data               = array();
        $data['token']      = $token;
        $data['public_key'] = $new_public_key;
        

        /** Let the user modify the data before send it back */
        // todo: docbloc
        $data = apply_filters( 'token_auth_token_before_dispatch_generate', $data, $user );
        return json_encode( $data );
    }

    /**
     * This is our middleware to try to authenticate the user according to the
     * token send.
     *
     * @param (int|bool) $user Logged User ID
     *
     * @return (int|bool)
     */
    public function determine_current_user( $user ) {
        // Don't authenticate twice
        if ( ! empty( $user ) ) {
            return $user;
        }

        /*
         * if the request URI is for validate the token don't do anything,
         * this avoid double calls to the validate_token function.
         */
        $validate_uri = strpos( $_SERVER['REQUEST_URI'], 'token/validate');
        if ( $validate_uri > 0 ) {
            return $user;
        }

        $token = $this->validate_token( false );

        if ( is_wp_error( $token ) ) {
            /** If there is a error, store it to show it after see rest_pre_dispatch */
            $this->token_error = $token;
            return $user;
        }
        /** Everything is ok, return the user ID */
        return $token;
    }

    /**
     * Main validation function, this function try to get the Autentication
     * headers and decoded.
     *
     * @param bool $output
     *
     * @return WP_Error | Object
     */
    public function validate_token( $output = true ) {
        // Check that we're trying to authenticate
        if ( ! isset( $_SERVER['HTTP_X_WP_AUTH_KEY'] ) ) {
			return $user;
        }

        $public_key = $_SERVER['HTTP_X_WP_AUTH_KEY'];
        $token      = $_SERVER['HTTP_X_WP_AUTH_TOKEN'];

        if ( empty( $public_key ) ) {
            return new WP_Error(
                'token_auth_no_key_to_validate',
                __('Public key not sent.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        if ( empty( $token ) ) {
            return new WP_Error(
                'token_auth_no_token_to_validate',
                __('Token not sent.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        // todo: string length checks
        // todo: fail2ban

        if ( ! ( $user = $this->get_user( $public_key ) ) ) {
            return new WP_Error(
                'token_auth_invalid_public_key_validated',
                __('Your request could not be authenticated. Invalid public key.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        } else {
            $token  = $token;
            $secret = $this->get_user_secret_key( $user );
            $public = $public_key;

            if ( hash_equals( md5( $secret . $public ), $token ) ) {
                return $user;
            } else {
                return new WP_Error(
                    'token_auth_invalid_auth_validated',
                    __('Your request could not be authenticated.', 'wp-api-token-auth'),
                    array(
                        'status' => 403,
                    )
                );
            }
        }
    }

    // todo: docbloc
    /**
     * 
     *
     * @param [type] $request [description]
     *
     * @return [type] [description]
     */
    public function revoke_token( $request ) {
        $token = $this->validate_token( false );

        if ( is_wp_error( $token ) ) {
            /** If there is a error, store it to show it after see rest_pre_dispatch */
            $this->token_error = $token;
            return $token;
        }

        $public_key = $this->get_user_public_key( $token );
        $secret_key = $this->get_user_secret_key( $token );
        if ( ! empty( $public_key ) ) {
            delete_transient( md5( 'rest_api_token_auth_cache_user_' . $public_key ) );
            delete_transient( md5( 'rest_api_token_auth_cache_user_public_key' . $token ) );
            delete_transient( md5( 'rest_api_token_auth_cache_user_secret_key' . $token ) );
            delete_user_meta( $token, 'rest_api_token_auth_public_key' );
            delete_user_meta( $token, 'rest_api_token_auth_secret_key' );
        } else {
            return new WP_Error(
                'token_auth_revoke_keys_dont_exist',
                __('Keys do not exist.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Everything is ok, return 'OK' */    
        return 'OK';
    }

    // todo: docbloc
    /**
     * 
     *
     * @param [type] $request [description]
     *
     * @return [type] [description]
     */
    public function regenerate_token( $request ) {
        $user_id = $this->validate_token( false );

        if ( is_wp_error( $user_id ) ) {
            /** If there is a error, store it to show it after see rest_pre_dispatch */
            $this->token_error = $user_id;
            return $user_id;
        }

        $public_key = $this->get_user_public_key( $user_id );
        $secret_key = $this->get_user_secret_key( $user_id );
        if ( ! empty( $public_key ) ) {
            delete_transient( md5( 'rest_api_token_auth_cache_user_' . $public_key ) );
            delete_transient( md5( 'rest_api_token_auth_cache_user_public_key' . $user_id ) );
            delete_transient( md5( 'rest_api_token_auth_cache_user_secret_key' . $user_id ) );
            delete_user_meta( $user_id, 'rest_api_token_auth_public_key' );
            delete_user_meta( $user_id, 'rest_api_token_auth_secret_key' );
        } else {
            return new WP_Error(
                'token_auth_revoke_keys_dont_exist',
                __('Keys do not exist.', 'wp-api-token-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        $user               = $user = $this->get_user( $user_id );

        $new_public_key     = $this->generate_public_key( $user->user_email );
        $new_secret_key     = $this->generate_private_key( $user->ID );

        update_user_meta( $user_id, 'rest_api_token_auth_public_key', $new_public_key );
        update_user_meta( $user_id, 'rest_api_token_auth_secret_key', $new_secret_key );        
    
        $token              = $this->get_token( $user_id );

        $data               = array();
        $data['token']      = $token;
        $data['public_key'] = $new_public_key;
        

        /** Let the user modify the data before send it back */
        // todo: docbloc
        $data = apply_filters( 'token_auth_token_before_dispatch_regenerate', $data, $user );
        return json_encode( $data );
    }


    /**
     * Retrieve the user ID based on the public key provided
     *
     * @access public
     * @since 1.0.0
     * @global object $wpdb Used to query the database using the WordPress
     * Database API
     *
     * @param string $key Public Key
     *
     * @return bool if user ID is found, false otherwise
     */
    public function get_user( $key = '' ) {
        global $wpdb;

        if ( empty( $key ) ) {
            return false;
        }

        $user = get_transient( md5( 'rest_api_token_auth_cache_user_' . $key ) );

        if ( false === $user ) {
            $user = $wpdb->get_var( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = 'rest_api_token_auth_public_key' AND meta_value = %s LIMIT 1", $key ) );
            set_transient( md5( 'rest_api_token_auth_cache_user_' . $key ) , $user, DAY_IN_SECONDS );
        }

        if ( $user != NULL ) {
            $this->user_id = $user;
            return $user;
        }

        return false;
    }

    // todo: docbloc
    /**
     * 
     *
     * @param [type] $user_id [description]
     *
     * @return [type] [description]
     */
    public function get_user_public_key( $user_id = 0 ) {
        global $wpdb;

        if ( empty( $user_id ) ) {
            return '';
        }

        $cache_key       = md5( 'rest_api_token_auth_cache_user_public_key' . $user_id );
        $user_public_key = get_transient( $cache_key );

        if ( empty( $user_public_key ) ) {
            $user_public_key = $wpdb->get_var( $wpdb->prepare( "SELECT meta_value FROM $wpdb->usermeta WHERE meta_key = 'rest_api_token_auth_public_key' AND user_id = %d", $user_id ) );
            set_transient( $cache_key, $user_public_key, HOUR_IN_SECONDS );
        }

        return $user_public_key;
    }

    // todo: docbloc
    /**
     * 
     *
     * @param [type] $user_id [description]
     *
     * @return [type] [description]
     */
    public function get_user_secret_key( $user_id = 0 ) {
        global $wpdb;

        if ( empty( $user_id ) ) {
            return '';
        }

        $cache_key       = md5( 'rest_api_token_auth_cache_user_secret_key' . $user_id );
        $user_secret_key = get_transient( $cache_key );

        if ( empty( $user_secret_key ) ) {
            $user_secret_key = $wpdb->get_var( $wpdb->prepare( "SELECT meta_value FROM $wpdb->usermeta WHERE meta_key = 'rest_api_token_auth_secret_key' AND user_id = %d", $user_id ) );
            set_transient( $cache_key, $user_secret_key, HOUR_IN_SECONDS );
        }

        return $user_secret_key;
    }

    /**
     * Revoke a users API keys
     *
     * @access public
     * @author Chris Christoff
     * @since  1.0.0
     * @param  int $user_id User ID of user to revoke key for
     * @return string
     */
    public function revoke_api_key( $user_id = 0 ) {

        if( empty( $user_id ) ) {
            return false;
        }

        $user = get_userdata( $user_id );

        if( ! $user ) {
            return false;
        }

        $public_key = $this->get_user_public_key( $user_id );
        $secret_key = $this->get_user_secret_key( $user_id );
        if ( ! empty( $public_key ) ) {
            delete_transient( md5( 'rest_api_token_auth_cache_user_' . $public_key ) );
            delete_transient( md5( 'rest_api_token_auth_cache_user_public_key' . $user_id ) );
            delete_transient( md5( 'rest_api_token_auth_cache_user_secret_key' . $user_id ) );
            delete_user_meta( $user_id, $public_key );
            delete_user_meta( $user_id, $secret_key );
        } else {
            return false;
        }

        return true;
    }   

    /**
     * Generate and Save API key
     *
     * Generates the key requested by user_key_field and stores it in the database
     *
     * @access public
     * @author Chris Christoff
     * @since 1.0.0
     * @param int $user_id
     * @return void
     */
    public function update_key( $user_id ) {
        if ( current_user_can( 'edit_user', $user_id ) && isset( $_POST['rest_api_token_auth_set_api_key'] ) ) {

            $user = get_userdata( $user_id );

            $public_key = $this->get_user_public_key( $user_id );
            $secret_key = $this->get_user_secret_key( $user_id );

            if ( empty( $public_key ) ) {
                $new_public_key = $this->generate_public_key( $user->user_email );
                $new_secret_key = $this->generate_private_key( $user->ID );

                update_user_meta( $user_id, 'rest_api_token_auth_public_key', $new_public_key );
                update_user_meta( $user_id, 'rest_api_token_auth_secret_key', $new_secret_key );
            } else {
                $this->revoke_api_key( $user_id );
            }
        }
    }

    /**
     * Generate the public key for a user
     *
     * @access private
     * @author Chris Christoff
     * @since  1.0.0
     * @param  string $user_email
     * @return string
     */
    private function generate_public_key( $user_email = '' ) {
        $auth_key = defined( 'AUTH_KEY' ) ? AUTH_KEY : '';
        $public   = hash( 'md5', $user_email . $auth_key . date( 'U' ) );
        return $public;
    }

    /**
     * Generate the secret key for a user
     *
     * @access private
     * @author Chris Christoff
     * @since  1.0.0
     * @param  int $user_id
     * @return string
     */
    private function generate_private_key( $user_id = 0 ) {
        $auth_key = defined( 'AUTH_KEY' ) ? AUTH_KEY : '';
        $secret   = hash( 'md5', $user_id . $auth_key . date( 'U' ) );
        return $secret;
    }

    /**
     * Generate new API keys for a user
     *
     * @access public
     * @author Chris Christoff
     * @since  1.0.0
     * @param  int $user_id User ID the key is being generated for
     * @param  boolean $regenerate Regenerate the key for the user
     * @return boolean True if (re)generated succesfully, false otherwise.
     */
    public function generate_api_key( $user_id = 0, $regenerate = false ) {

        if ( empty( $user_id ) ) {
            return false;
        }

        $user = get_userdata( $user_id );

        if ( ! $user ) {
            return false;
        }

        $public_key = $this->get_user_public_key( $user_id );
        $secret_key = $this->get_user_secret_key( $user_id );

        if ( empty( $public_key ) || $regenerate == true ) {
            $new_public_key = $this->generate_public_key( $user->user_email );
            $new_secret_key = $this->generate_private_key( $user->ID );
        } else {
            return false;
        }

        if ( $regenerate == true ) {
            $this->revoke_api_key( $user->ID );
        }

        update_user_meta( $user_id, 'rest_api_token_auth_public_key', $new_public_key );
        update_user_meta( $user_id, 'rest_api_token_auth_secret_key', $new_secret_key );

        return true;
    }

    /**
     * Retrieve the user's token
     *
     * @access private
     * @author Chris Christoff
     * @since  1.0.0
     * @param  int $user_id
     * @return string
     */
    public function get_token( $user_id = 0 ) {
        return hash( 'md5', $this->get_user_secret_key( $user_id ) . $this->get_user_public_key( $user_id ) );
    }

    /**
     * Filter to hook the rest_pre_dispatch, if the is an error in the request
     * send it, if there is no error just continue with the current request.
     *
     * @access public
     * @author Chris Christoff
     * @since  1.0.0
     * @param  $request
     * @return string 
     */
    public function rest_pre_dispatch( $request ) {
        if ( is_wp_error( $this->token_error ) ) {
            return $this->token_error;
        }
        return $request;
    }

    /**
     * Modify User Profile
     *
     * Modifies the output of profile.php to add key generation/revocation
     *
     * @access public
     * @author Chris Christoff
     * @since 1.0.0
     * @param object $user Current user info
     * @return void
     */
    function user_key_field( $user ) {
        if ( current_user_can( 'manage_options', $user->ID ) ) {
            $user = get_userdata( $user->ID );
            ?>
            <table class="form-table">
                <tbody>
                    <tr>
                        <th>
                            <?php _e( 'WordPress REST Token Authentication API Keys', 'wp-api-token-auth' ); ?>
                        </th>
                        <td>
                            <?php
                                $public_key = $this->get_user_public_key( $user->ID );
                                $secret_key = $this->get_user_secret_key( $user->ID );
                            ?>
                            <?php if ( empty( $user->rest_api_token_auth_public_key ) ) { ?>
                                <input name="rest_api_token_auth_set_api_key" type="checkbox" id="rest_api_token_auth_set_api_key" value="0" />
                                <span class="description"><?php _e( 'Generate API Key', 'wp-api-token-auth' ); ?></span>
                            <?php } else { ?>
                                <strong style="display:inline-block; width: 125px;"><?php _e( 'Public key:', 'wp-api-token-auth' ); ?>&nbsp;</strong><input type="text" disabled="disabled" class="regular-text" id="publickey" value="<?php echo esc_attr( $public_key ); ?>"/><br/>
                                <strong style="display:inline-block; width: 125px;"><?php _e( 'Secret key:', 'wp-api-token-auth' ); ?>&nbsp;</strong><input type="text" disabled="disabled" class="regular-text" id="privatekey" value="<?php echo esc_attr( $secret_key ); ?>"/><br/>
                                <strong style="display:inline-block; width: 125px;"><?php _e( 'Token:', 'wp-api-token-auth' ); ?>&nbsp;</strong><input type="text" disabled="disabled" class="regular-text" id="token" value="<?php echo esc_attr( $this->get_token( $user->ID ) ); ?>"/><br/>
                                <input name="rest_api_token_auth_set_api_key" type="checkbox" id="rest_api_token_auth_set_api_key" value="0" />
                                <span class="description"><label for="rest_api_token_auth_set_api_key"><?php _e( 'Revoke API Keys', 'wp-api-token-auth' ); ?></label></span>
                            <?php } ?>
                        </td>
                    </tr>
                </tbody>
            </table>
        <?php }
    }

    /**
     * Process an API key generation/revocation
     *
     * @access public
     * @since 1.0.0
     * @param array $args
     * @return void
     */
    public function process_api_key( $args ) {

        if ( ! wp_verify_nonce( $_REQUEST['_wpnonce'], 'wp-api-token-auth-nonce' ) ) {

            wp_die( __( 'Nonce verification failed', 'wp-api-token-auth' ), __( 'Error', 'wp-api-token-auth' ), array( 'response' => 403 ) );

        }

        if ( is_numeric( $args['user_id'] ) ) {
            $user_id    = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : get_current_user_id();
        } else {
            $userdata   = get_user_by( 'login', $args['user_id'] );
            $user_id    = $userdata->ID;
        }
        $process    = isset( $args['rest_api_token_auth_process'] ) ? strtolower( $args['rest_api_token_auth_process'] ) : false;

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( sprintf( __( 'You do not have permission to %s API keys for this user', 'wp-api-token-auth' ), $process ), __( 'Error', 'wp-api-token-auth' ), array( 'response' => 403 ) );
        }

        switch( $process ) {
            case 'generate':
                if ( $this->generate_api_key( $user_id ) ) {
                    delete_transient( 'rest-api-token-auth-total-api-keys' );
                    wp_redirect( add_query_arg( 'rest-api-token-auth-message', 'api-key-generated', 'tools.php?page=rest_api_token_auth_page' ) ); exit();
                } else {
                    wp_redirect( add_query_arg( 'rest-api-token-auth-message', 'api-key-failed', 'tools.php?page=rest_api_token_auth_page' ) ); exit();
                }
                break;
            case 'regenerate':
                $this->generate_api_key( $user_id, true );
                delete_transient( 'rest-api-token-auth-total-api-keys' );
                wp_redirect( add_query_arg( 'rest-api-token-auth-message', 'api-key-regenerated', 'tools.php?page=rest_api_token_auth_page' ) ); exit();
                break;
            case 'revoke':
                $this->revoke_api_key( $user_id );
                delete_transient( 'rest-api-token-auth-total-api-keys' );
                wp_redirect( add_query_arg( 'rest-api-token-auth-message', 'api-key-revoked', 'tools.php?page=rest_api_token_auth_page' ) ); exit();
                break;
            default;
                break;
        }
    }

}

