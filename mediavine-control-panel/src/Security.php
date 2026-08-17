<?php

namespace Mediavine\MCP;

/**
 * Handles functionality related to CSP.
 */
class Security {

	/**
	 * Reference to static singleton self.
	 *
	 * @property self $instance
	 */
	use \Mediavine\MCP\Traits\Singleton;

	/**
	 * Capability required to change any plugin setting.
	 *
	 * Matches the capability the settings UI itself gates these controls on.
	 *
	 * @var string
	 */
	const MANAGE_SETTINGS_CAPABILITY = 'manage_options';

	/**
	 * Security constructor.
	 *
	 * @codeCoverageIgnore
	 */
	public function __construct() {
		$this->init_plugin_actions();
	}

	/**
	 * Initialize plugin hooks.
	 *
	 * @codeCoverageIgnore
	 */
	public function init_plugin_actions() {
		add_action( 'send_headers', array( $this, 'send_headers' ) );
		add_action( 'admin_notices', array( $this, 'admin_notices' ) );
	}

	/**
	 * Verify an admin-ajax request is both intentional and authorized.
	 *
	 * A nonce only proves the request was deliberate; it grants no privileges
	 * and is readable by any logged-in user the page is rendered for. Endpoints
	 * that change plugin settings must therefore also check the current user's
	 * capabilities. Ends the request with a 403 when either check fails.
	 *
	 * @param string $nonce_action Action string the nonce was created with.
	 * @param string $capability   Capability required to perform the action.
	 */
	public static function verify_admin_ajax_request( $nonce_action, $capability = self::MANAGE_SETTINGS_CAPABILITY ) {
		check_ajax_referer( $nonce_action );

		if ( ! current_user_can( $capability ) ) {
			wp_die( -1, 403 );
		}
	}

	/**
	 * Adds a CSP header to pages.
	 */
	public function send_headers() {
		// Don't send CSP headers if on Customizer.
		$customizer = false;
		if ( function_exists( 'is_customize_preview' ) && is_customize_preview() ) {
			$customizer = true;
		}

		if ( Option::get_instance()->get_option_bool( 'block_mixed_content' ) && ! $customizer ) {
			// The catch here should only happen during unit tests and not during a normal WP bootstrap.
			try {
				header( 'Content-Security-Policy: block-all-mixed-content' );
			} catch ( \Exception $e ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Shows a notice in admin if users have an invalid combination of settings.
	 */
	public function admin_notices() {
		$option = Option::get_instance();
		if ( $option->get_option_bool( 'enable_forced_ssl' ) && ! $option->get_option_bool( 'block_mixed_content' ) ) {
			echo '<div class="notice notice-warning is-dismissible">
            <p><strong>Mediavine Control Panel</strong> &raquo; Your Content Security Policy is no longer supported. Please <a href="options-general.php?page=' . esc_attr( MV_Control_Panel::PLUGIN_DOMAIN ) . '">update your security settings</a>.</p>
            </div>';
		}
	}
}
