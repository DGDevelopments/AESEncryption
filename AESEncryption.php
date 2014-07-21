<?php
/**
 *
 *  @package AESEncryption
 *  @author DGDevelopments
 *  @license http://opensource.org/licenses/gpl-2.0.php
 */





class AESEncryption {

    public function Encrypt ($String){
        /*
         * Encrypts provided string and condenses vital information into a single string
         *
         *  @param | string | $String The string to be encrypted using AES
         *  @return an encrypted string with other vital information condensed into a single string
         */
        $Size = mcrypt_get_iv_size(MCRYPT_CAST_256,MCRYPT_MODE_CBC);
        $IV = mcrypt_create_iv($Size,MCRYPT_RAND);
        $Hash = strlen($String);

        $Encrypted_String = openssl_encrypt($String, "AES-256-CBC",$Hash,0,$IV);
        $Hash_Count = count(str_split($Hash));
        $EncStr_Arr = str_split($Encrypted_String);
        $Count = strlen($IV);
        $Increment = 0;
        $Return_String = "";
        $Return_String .= $Hash_Count.$Count.$Hash;
        while ($Increment < $Count){

            $Return_String .= $IV[$Increment];
            $Return_String .= $Encrypted_String[$Increment];
            unset($EncStr_Arr[$Increment]);
            $Increment++;
        }

        $Encrypted_String = implode("",$EncStr_Arr);
       return $Return_String.$Encrypted_String;
    }


    public function Decrypt ($String){
    /*
     *  Manipulate string data to obtain the correct information to decrypt an encrypted string
     *
     *  @param | string | The encrypted string
     *  @return a decrypted string using the information provided in $string
     */
        $String_Array = str_split($String);

        $Hash_Count = $String_Array[0];
        unset($String_Array[0]);
        $IVLength = $String_Array[1].$String_Array[2];
        $Hash = NULL;
        unset($String_Array[1]);
        unset($String_Array[2]);
        $Hash_Incrementer = 0;
        $String_Array = array_values($String_Array);
        while ($Hash_Incrementer < $Hash_Count){

            $Hash .= $String_Array[$Hash_Incrementer];
            unset($String_Array[$Hash_Incrementer]);

            $Hash_Incrementer++;

        }

        array_unshift($String_Array, null);
        unset($String_Array[0]);

        $IV = null;
        $Encrypted_String = null;
        foreach ($String_Array AS $Key => $Value){

            if($Key&1) {
                $IV .= $Value;

            } else {
                $Encrypted_String .= $Value;
            }
            unset($String_Array[$Key]);
            if ($IVLength*2 == $Key){
                break;
            }
        }

        return openssl_decrypt($Encrypted_String.implode("",$String_Array),"AES-256-CBC",(int)$Hash,0,$IV);
    }


} // End Class