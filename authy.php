<?php
/**
 * Plugin Name: Authy by Marcus Battle
 */

remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );

add_action( 'login_header', 'remove_password_field' );

function remove_password_field() {
	?>
		<style>label[for="user_pass"], .forgetmenot { display: none; }</style>
	<?php
}

add_action( 'login_header', 'remove_username_field' );

function remove_username_field() {

	$action = $_GET['action'] ?? '';

	if ( 'verify' !== $action ) {
		return;
	}

	?>
		<style>label[for="user_login"] { display: none; }</style>
	<?php
}

add_action( 'login_form', 'add_token_field' );

/**
 * Replace the password field with one for the user's mobile number.
 */
function add_token_field() {

	$action   = $_GET['action'] ?? '';
	$username = $_GET['log'] ?? '';

	if ( 'verify' !== $action ) {
		return;
	}

    ?>
		<p>
			<label for="authy_token"><?php _e( 'Enter security code sent to your phone.', 'authybymarcus' ) ?>
				<br />
				<input type="text" name="authy_token" id="authy-token" class="input" value="" />
			</label>
			<input type="hidden" name="username" value="<?php echo esc_attr( $username ); ?>" />
		</p>
    <?php
}

add_filter( 'authenticate', 'invoke_authentication', 50, 3 );

function invoke_authentication( $user, $username, $password ) {

	// Return no errors if the user is NULL.
	if ( null === $user && empty( $username ) ) {
		return new WP_Error('', '');
	}

	// Check to see if Authy is enabled.
	$authy_enabled  = true;

	if ( ! $authy_enabled ) {
		return $user;
	}

	// Retrieve the user.
	$user = get_user_by( 'login', $username );

	if ( ! $user ) {
		return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid username or email address.' ) );
	}

	// Get the user's authy_ID.
	$authy_ID = get_user_meta( $user->ID, 'authy_ID', true );

	if ( ! $authy_ID ) {
		return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: 2FA is not enabled for this user.' ) );
	}

	$response = authenticate_via_authy( $authy_ID );

	if ( $response->success ) {
		wp_safe_redirect( wp_login_url() . '?action=verify&log=' . $username );
	}

	return $user = new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: This user could not be authenticated.' ) );
}

function authenticate_via_authy( string $authy_ID ) {

	$response = wp_remote_get( "http://api.authy.com/protected/json/sms/{$authy_ID}", [
		'headers' => [
			'X-Authy-API-Key' => get_option( 'twilio_authy_app_ID' ),
		]
	] );

	$response_body = json_decode( wp_remote_retrieve_body( $response ) );

	return $response_body;
}

add_filter( 'authenticate', 'verify_authentication', 50 );

function verify_authentication( $user ) {

	$token    = $_POST['authy_token'] ?? '';
	$username = $_POST['username'] ?? '';

	if ( ! $token ) {
		return $user;
	}

	// Retrieve the user.
	$user = get_user_by( 'login', $username );

	if ( ! $user ) {
		return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid username or email address.' ) );
	}

	// Get the user's authy_ID.
	$authy_ID = get_user_meta( $user->ID, 'authy_ID', true );

	$response = verify_via_authy( $token, $authy_ID );

	if ( $response->success ) {
		return $user;
	}
}

function verify_via_authy( int $token, string $authy_ID ) {

	$response = wp_remote_get( "https://api.authy.com/protected/json/verify/{$token}/{$authy_ID}", [
		'headers' => [
			'X-Authy-API-Key' => get_option( 'twilio_authy_app_ID' ),
		]
	] );

	$response_body = json_decode( wp_remote_retrieve_body( $response ) );

	return $response_body;
}
