<?php
class DjangoSession {
    private $djangoSessionStoreClass = "django.contrib.sessionsSessionStore"; //django.contrib.sessionsSessionStore, django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash
    private $djangoSecret = ""; //put your SECRET_KEY here

    public function salted_hmac($key_salt, $value, $secret = NULL) {
        if (is_null($secret)) {
            $secret = $this->djangoSecret;
        }
        $key = sha1($key_salt . $secret, true);
        return hash_hmac("sha1", $value, $key, false);
    }
    
    private function hash($value, $key_salt = null) {
        if($key_salt == null) {
            $key_salt = $this->djangoSessionStoreClass;
        }
        return $this->salted_hmac($key_salt, $value);
    }

    /**
    * Encodes the session data
    */
    public function encode($data=array()) {
        $serialized = json_encode($data);
        $hash = $this->hash($serialized);
        return base64_encode($hash.':'.$serialized);
    }

    /**
    * Decodes Session Data
    */
    public function decode($dataStr) {
        $encoded_data = base64_decode($dataStr);
        $tmp = explode(":", $encoded_data, 2);
        $hash = $tmp[0];
        $serialized = $tmp[1];
        $expected_hash = $this->hash($serialized);
        
        if($hash != $expected_hash) {
            throw new Exception("DjangoSession: Session Data corrupted (hashes don't match)");
        }
        $data = json_decode($serialized, true);
        return $data;
    }
    
    /**
    * Generates the _auth_user_hash that must be present in the session for django. It is generated from the users password hash (the password field in the database)
    */
    public function getSessionAuthHash($userPasswordHash) {
        return $this->salted_hmac("django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash", $userPasswordHash);
    }
    
}

//TESTING
//Put the encrypted Data from the Session table (django_session->session_data)
$data = "NDlmODk0YWM1MzJhMzQ1Zjg4NDY0OTkzNjcxN2FmNGJ...";

//Put the user Password (auth_user->password)
$userPasswordHash = 'md5$4Vt0Yh6QDnto$cf30f0e1a3c0cadf...';

$sess = new DjangoSession();
$sessData = $sess->decode($data);
var_dump($sessData);

$authHash = $sess->getSessionAuthHash($userPasswordHash);
if($authHash != $sessData["_auth_user_hash"]) {
    die("Session Auth Hash don't match!\n");
}

$encrypted = $sess->encode($sessData);
if($encrypted != $data) {
    echo "Encrypted Data is corrupted!\n";
} else {
    echo "All good!\n";
}
