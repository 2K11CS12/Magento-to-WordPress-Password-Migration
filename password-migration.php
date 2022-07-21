<?php

/*
Plugin Name: Magento to WP Password Migration
Description: Let customers successfully log in to their accounts after Magento password migrations.
Version: 1.0
Author: Kalim Ullah
*/


add_filter( 'check_password', 'bp_magento_check_password', 10, 4 );

function bp_magento_check_password( $check, $password, $hash, $user_id ) {

    if ( $check ) {
    	// the password is already accepted
    	// do nothing further
        return $check;
    }

    $mg_password = get_user_meta( $user_id, 'bp_magento_pwd', true );
    $password_info = info($mg_password);
    
    if( $password_info['algoName'] == 'bcrypt' ){
        $passCheck = bcrypt_check($password, $mg_password);
    }else{
        // md5
        $magento_pwd_parts = explode(':', $mg_password);
    }
    
    
    if (
        ($password_info['algoName'] == 'bcrypt' && !$passCheck)// the results are false
        || ($password_info['algoName'] == 'unknown'
        && (! $magento_pwd_parts // the string exploded was empty
        || ! is_array( $magento_pwd_parts ) // result is not an array
        || ! sizeof( $magento_pwd_parts )) // the results are an empty array
        )) {
            // exit early if we were unable to retrieve a Magento hashed password
            // from User Meta
            return $check;
    }

    if( $password_info['algoName'] == 'unknown' ){
        $mHash = $magento_pwd_parts['0'];
        $mSalt = $magento_pwd_parts['1'];
        
        $passCheck = md5($mSalt.$password) ==  $mHash;
    }

    if ( $passCheck ) {
        // success, allow the user to log in

        // update WordPress to use this password
        wp_set_password( $password, $user_id );
        // delete Magento password from User Meta
        delete_user_meta( $user_id, 'bp_magento_pwd' );

        return true;
    }

    return $check;
}

/**
 * Hash the given value.
 *
 * @param  string  $value
 * @param  array  $options
 * @return string
 *
 */
function make($value, array $options = ['cost' => 10]){
    $hash = password_hash($value, PASSWORD_BCRYPT, [
        'cost' => $options['cost'],
    ]);

    if ($hash === false) {
        return false;
    }

    return $hash;
}


/**
 * Check the given plain value against a hash.
 *
 * @param  string  $value
 * @param  string  $hashedValue
 * @param  array  $options
 * @return bool
 */
function bcrypt_check($value, $hashedValue, array $options = []){
    if (strlen($hashedValue) === 0) {
        return false;
    }

    return password_verify($value, $hashedValue);
}

/**
 * Get information about the given hashed value.
 *
 * @param  string  $hashedValue
 * @return array
 */
function info($hashedValue){
    return password_get_info($hashedValue);
}