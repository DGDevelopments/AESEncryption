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

   public function Encrypt ($String){
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

   public function Merge($Array){
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
     #  $Array = $this->Encrypt($String);
        $Encrypted_String = $Array['EncryptedString'];
        $IV = $Array['IV'];
        $Hash = $Array['Hash'];
        $Hash_Count = count(str_split($Hash));
        $EncStr_Arr = str_split($Encrypted_String);
        $Count = strlen($IV);
        $Increment = 0;
        $String = "";
            // NEW: Appending the Hash Count, to be used in later functions. So The correct Hash can be obtained.
        $String .= $Hash_Count.$Count.$Hash; // Append the Count and Hash (as EncryptedString and IV are different lengths. Used to compensate
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
         *      1) Split the String into an Array, 1 character = 1 element
         *      2) The hash count is obtained (pushed to first character in the merge)
         *      3) Unset the Hash Number
         *      4) IV length is stored and created into the 2 digit number to be used later
         *      5) Unset the IV Containers in elements 1 & 2
         *      6) Reset the Array Index to 0
         *      7) See While loop Comments
         *
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
           /*
            *  Use a while loop to pull correct Hash number from the string & unsetting as we go
            */
           $Hash .= $String_Array[$Hash_Incrementer];
           unset($String_Array[$Hash_Incrementer]);

           $Hash_Incrementer++;

       }
       /*
        *  Increment the array values to start from 1 instead of 0
        */
       array_unshift($String_Array, null);
       unset($String_Array[0]);

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
            if ($IVLength*2 == $Key){
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


   public function Debug($String){
        $Step_1 = $this->Encrypt($String);
        $Step_2 = $this->Merge($Step_1);
        $Step_3 = $this->UnMerge($Step_2);
        $Step_4 = $this->Decrypt($Step_3);

       $Return_Array = array();

       if ($Step_1['EncryptedString'] === $Step_3['EncryptedString']){
           $Return_Array[] = "Encryption Strings match on Unmerging & Encryption";
       }else{
           $Return_Array['Errors']["EncryptedString"] = array(
               "Encryption String on Encryption and Unmerging does not match",
               "Encryption" => $Step_1['EncryptedString'],
               "Unmerging" => $Step_2['EncryptedString']
           );
       }
       if ($Step_1['IV'] === $Step_3['IV']){
           $Return_Array[] = "IV Strings match on Unmerging & Encryption";
       }else{
           $Return_Array['Errors']["IV"] = array(
               "IV String on Encryption and Unmerging does not match",
               "Encryption_IV" => $Step_1['IV'],
               "Unmerging_IV" => $Step_2['IV']
           );
       }
       if ($Step_1['Hash'] === $Step_3['Hash']){
           $Return_Array[] = "Hash Strings match on Unmerging & Encryption";
       }else{
           $Return_Array['Errors']["Hash"] = array(
               "Hash String on Encryption and Unmerging does not match",
               "Encryption_IV" => $Step_1['IV'],
               "Unmerging_IV" => $Step_2['IV']
           );
       }
       if ($Step_4 === $String){
           $Return_Array[] = "Passed Data Successfully Decrypted";
       }else{
           $Return_Array['Errors']['String'] = "Error Encountered. Encrypted and Decrypted Strings Do Not Match";
       }

       return $Return_Array;
   }



} // End Class