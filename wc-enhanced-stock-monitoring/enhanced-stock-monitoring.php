/**
 * Enhanced Stock Query Monitor Filter
 * 
 * This filter monitors and logs all database queries related to WooCommerce stock management
 * to help identify potential performance issues, unauthorized stock modifications, or
 * problematic plugins that may be causing excessive database load.
 * 
 * What it monitors:
 * - Queries containing '_postmeta' table references
 * - Queries related to stock ('_stock') or backorders ('_backorders')
 * - Excludes SELECT queries and order stock reduction queries
 * 
 * What it logs:
 * - Full SQL query details
 * - User information and authentication details
 * - Request context (REST API, AJAX, Cron, CLI, etc.)
 * - Complete backtrace with file paths and line numbers
 * - Plugin identification for non-core files
 * - External system indicators and headers
 * - WooCommerce-specific webhook and API details
 * 
 * Logging destinations:
 * - WooCommerce logger (if available)
 * - WordPress debug log (if WP_DEBUG is enabled)
 * 
 * @since 1.0.0
 * @author Daniel Kam + Cursor AI
 * @package Enhanced Stock Monitor
 * 
 * @param string $query The SQL query being executed
 * @return string The original query (unchanged)
 */
add_filter('query', function($query) {
    if (
        stripos($query, '_postmeta') !== false &&
        (stripos($query, '_stock') !== false OR stripos($query, '_backorders') !== false) &&
        stripos(ltrim($query), 'SELECT') !== 0 &&
        stripos($query, '_order_stock_reduced') === false
    ){
        
        // Get detailed backtrace with file paths and line numbers
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20);
        
        // Build detailed debug info
        $debug_info = array(
            'query' => $query,
            'timestamp' => current_time('mysql'),
            'user_id' => get_current_user_id(),
            'username' => wp_get_current_user()->user_login ?? 'Unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'Unknown',
            'http_method' => $_SERVER['REQUEST_METHOD'] ?? 'Unknown',
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
            'backtrace' => array()
        );
        
        // Process backtrace to find relevant info
        foreach ($backtrace as $index => $trace) {
            if (isset($trace['file']) && isset($trace['line'])) {
                $file_path = str_replace(ABSPATH, '', $trace['file']);
                
                // Check if it's a plugin file
                if (strpos($file_path, 'wp-content/plugins/') !== false) {
                    $plugin_name = explode('/', $file_path)[2]; // Get plugin folder name
                    $debug_info['backtrace'][] = array(
                        'index' => $index,
                        'file' => $file_path,
                        'line' => $trace['line'],
                        'function' => $trace['function'] ?? 'Unknown',
                        'class' => $trace['class'] ?? 'Unknown',
                        'plugin' => $plugin_name,
                        'type' => $trace['type'] ?? 'Unknown'
                    );
                } else {
                    $debug_info['backtrace'][] = array(
                        'index' => $index,
                        'file' => $file_path,
                        'line' => $trace['line'],
                        'function' => $trace['function'] ?? 'Unknown',
                        'class' => $trace['class'] ?? 'Unknown',
                        'plugin' => 'WordPress Core',
                        'type' => $trace['type'] ?? 'Unknown'
                    );
                }
            }
        }
        
        // Check if it's a cron job
        if (defined('DOING_CRON') && DOING_CRON) {
            $debug_info['trigger'] = 'WordPress Cron';
            $debug_info['cron_hook'] = get_transient('doing_cron') ?: 'Unknown';
        }
        
        // Enhanced REST API logging
        if (defined('REST_REQUEST') && REST_REQUEST) {
            $debug_info['trigger'] = 'REST API';
            $debug_info['rest_route'] = $_SERVER['REQUEST_URI'] ?? 'Unknown';
            
            // Get REST API authentication details (without sensitive keys)
            $debug_info['rest_auth'] = array(
                'user_id' => get_current_user_id(),
                'username' => wp_get_current_user()->user_login ?? 'Unknown',
                'auth_method' => $_SERVER['HTTP_AUTHORIZATION'] ? 'OAuth/Basic' : 'None'
            );
            
            // Get the actual REST API endpoint details
            $rest_server = rest_get_server();
            if ($rest_server) {
                $debug_info['rest_endpoint'] = array(
                    'route' => $rest_server->get_raw_data() ?: 'Unknown',
                    'method' => $_SERVER['REQUEST_METHOD'] ?? 'Unknown',
                    'namespace' => 'wc/v3', // WooCommerce REST API namespace
                    'resource' => 'products' // Based on the URI pattern
                );
            }
            
            // Check if it's coming from a specific plugin or external source
            $referer = $_SERVER['HTTP_REFERER'] ?? 'None';
            $debug_info['referer'] = $referer;
            
            // Check for common external system headers
            $debug_info['external_indicators'] = array(
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'None',
                'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 'None',
                'x_real_ip' => $_SERVER['HTTP_X_REAL_IP'] ?? 'None',
                'x_forwarded_host' => $_SERVER['HTTP_X_FORWARDED_HOST'] ?? 'None',
                'x_forwarded_proto' => $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'None'
            );
            
            // Check for WooCommerce specific headers (without sensitive data)
            $debug_info['wc_headers'] = array(
                'webhook_source' => $_SERVER['HTTP_X_WC_WEBHOOK_SOURCE'] ? 'Present' : 'None',
                'webhook_topic' => $_SERVER['HTTP_X_WC_WEBHOOK_TOPIC'] ?? 'None',
                'webhook_signature' => $_SERVER['HTTP_X_WC_WEBHOOK_SIGNATURE'] ? 'Present' : 'None'
            );
        }
        
        // Check if it's an AJAX call
        if (defined('DOING_AJAX') && DOING_AJAX) {
            $debug_info['trigger'] = 'AJAX';
            $debug_info['ajax_action'] = $_POST['action'] ?? $_GET['action'] ?? 'Unknown';
        }
        
        // Check if it's a CLI command
        if (defined('WP_CLI') && WP_CLI) {
            $debug_info['trigger'] = 'WP-CLI';
            $debug_info['cli_command'] = implode(' ', $_SERVER['argv'] ?? array());
        }
        
        // Check if it's a webhook
        if (defined('REST_REQUEST') && REST_REQUEST && 
            (strpos($_SERVER['REQUEST_URI'], 'webhooks') !== false || 
             isset($_SERVER['HTTP_X_WC_WEBHOOK_SOURCE']))) {
            $debug_info['trigger'] = 'WooCommerce Webhook';
            $debug_info['webhook_details'] = array(
                'source' => $_SERVER['HTTP_X_WC_WEBHOOK_SOURCE'] ?? 'Unknown',
                'topic' => $_SERVER['HTTP_X_WC_WEBHOOK_TOPIC'] ?? 'Unknown',
                'signature' => $_SERVER['HTTP_X_WC_WEBHOOK_SIGNATURE'] ? 'Present' : 'None'
            );
        }
        
        // Log the enhanced debug info
        if (function_exists('wc_get_logger')) {
            $logger = wc_get_logger();
            $logger->warning(
                'Enhanced Stock Monitor: ' . wc_print_r($debug_info, true), 
                array('source' => 'enhanced-stock-monitor')
            );
        }
        
        // Also log to WordPress debug log if enabled
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('Enhanced Stock Monitor: ' . print_r($debug_info, true));
        }
    }

    return $query;
});
