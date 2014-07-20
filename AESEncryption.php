<?php
/**
 * Created By: DGDevelopments
 * User: Daryl
 * Date: 20/07/14
 * Time: 00:02
 * Webpage: n/a
 * Copyright Daryls Developments
 */


class Encryption {

   protected function EncryContents ($String){
        /*
         *  Create an Encrypted String.
         *  @Var string
         *
         */
        $Size = mcrypt_get_iv_size(MCRYPT_CAST_256,MCRYPT_MODE_CBC);
        $iv = mcrypt_create_iv($Size,MCRYPT_RAND);
        $Hash = strlen($String);
        return
            array(
                "EncryptedString" => openssl_encrypt($String, "AES-256-CBC",$Hash,0,$iv),
                "IV" => $iv,
                "Hash" => $Hash
            );
    }

   public function Encrypt($String){
        /*
         *  Merge The Array Returned From the String Encryption into a string
         *
         *      Information:
         *          1) Convert Each Element from the array into their personal variables
         *          2) Create an Array from the first element. Will be used at the later stages
         *          3) Get the length of the current IV passed
         *          4) Create an empty string to be manipulated using the attaching loop
         *
         */
       $Array = $this->EncryContents($String);
        $Encrypted_String = $Array['EncryptedString'];
        $IV = $Array['IV'];
        $Hash = $Array['Hash'];
        $EncStr_Arr = str_split($Encrypted_String);
        $Count = strlen($IV);
        $Increment = 0;
        $String = "";
        $String .= $Count.$Hash; // Append the Count and Hash (as EncryptedString and IV are different lengths. Used to compensate
        While ($Increment < $Count){
            /*
             *  This loop appends to the string created in the order:
             *  Even: IV Character
             *  Odd: EncryptedString Character
             *
             *  Unset Elements of the Array for each iteration
             */
            $String .= $IV[$Increment];
            $String .= $Encrypted_String[$Increment];
            unset($EncStr_Arr[$Increment]);
            $Increment++;
        }
        /*
         *  After The loop has broken (Increment reaches the count of the IV), implode the Remainder elements (encrypted string)
         *  and return string + imploded array
         */
        $Encrypted_String = implode("",$EncStr_Arr);
        return $String.$Encrypted_String;
    }


   public function UnMerge($String){
        /*
         *  function splits a string into 3 elements of an array to a usable format for the decryption
         *      1) Split the string into an array, 1 character = 1 element
         *      2) IVlength is stored and created into the 2 digit number to be used later
         *      3) Get the hash created in StringMerge function
         *      4) Unset the first 3 elements as they provide no extra use
         *
         *
         */
        $String_Array = str_split($String);
        $IVLength = $String_Array[0].$String_Array[1];
        $Hash = $String_Array[2];
        unset($String_Array[0]);
        unset($String_Array[1]);
        unset($String_Array[2]);

        $IV = null;
        $Encryption = null;
        foreach ($String_Array AS $Key => $Value){
            /*
             * Through each iteration of the array (using the keys) decides if the key is odd or even.
             *  If odd: Appending to the empty $IV var
             *  If Even: Appending to the encrypted string
             */
            if($Key&1) {
                $IV .= $Value;
            } else {
                $Encryption .= $Value;
            }
            unset($String_Array[$Key]); // Unset as we go
            if ($IVLength*2+1 == $Key){
                /*
                 *
                 *  If Correct IV length is equal to the Key then end the foreach loop.
                 *
                 *
                 * Length after manipulation in earlier functions = 41
                 * Pushing the three extra elements into the array = 44
                 * IV Length Counted = 16.
                 *
                 *          Maths:
                 *              41 + 3 = 44
                 *              16*2 = 32 + 1 = 33
                 *              41 - 33 = 8 (Remainding Characters from the EncryptedString
                 */
                break;
            }
        }

        return array(
            /*
             * Return an Array with correct information to be used for Decryption.
             *  "EncryptedString" = What was pushed in earlire foreach with an imploded array of the remainding Chars
             *  "IV" = The Correct IV
             * "Hash" = A Type juggled integer containing the Hash as created in the Encryption
             */
            "EncryptedString" => $Encryption.implode("",$String_Array),
            "IV" => $IV,
            "Hash" => (int)$Hash
        );
    }

    function Decrypt($Array){
        /*
         *  Decrypt The Encrypted String with passing correct information as managed by UnMergeString
         */
        return openssl_decrypt($Array['EncryptedString'],"AES-256-CBC",$Array['Hash'],0,$Array['IV']);
    }



} // End Class