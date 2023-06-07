<?php
class RBAC_TokenProcessor{
    //token settings
    private $secretAppKey = "superSecretKey- dont sahare to anyone";
    
    private $cipherMethod = "aes-128-cbc";
    
    //magic number for random bytes
    private $IV = 0x0009999987656789;
    private $DB_host ;
    private $DB_username ;
    private $DB_password;
    private $DBName;
    private $loginTable;
    private $IDcollumn;
    private $passwordCollumn; 
  
    public function connection(){
        $pdoStr = "mysql:host=".$this->DB_host.";dbname=".$this->DBName.";charset=UTF8";
        try{
            $con = new PDO($pdoStr,$this->DB_username,$this->DB_password);
            if($con){
                
                return $con;
            }
        }
        catch(PDOException $e){
            return $e->getMessage();
        }
    }
    //make private after create
    public function RBACgetTokenDetail($token){
        $tokenDecrypted = openssl_decrypt($token,$this->cipherMethod,$this->secretAppKey,0,$this->IV);
        
        $tokenDecrypted =  explode("--::--",$tokenDecrypted);
        //return $tokenDecrypted;
        if(count($tokenDecrypted)!= 3 && $tokenDecrypted[2] != "tryThisMF)"){
            return array("status"=>"not a valid token");
        }else{
            
            return array("role"=>$tokenDecrypted[1],"ID"=>$tokenDecrypted[0]);
        }
    }


    public function RBACencrypt_token_for($user,$password){
        $role = "";
        $query = "select role from ".$this->loginTable." where ".$this->IDcollumn."= ? and ".$this->passwordCollumn." = ?";
        $stmt = $this->connection()->prepare($query);
        $stmt->execute([$user,$password]);
        $res =  $stmt->fetchAll();
        $encryptThis = "$user--::--".$res[0][0]."--::--tryThisMF)";
        if(count($res) > 0){
            return array(
                "status"=>"OK",
                "token"=>openssl_encrypt($encryptThis,$this->cipherMethod,$this->secretAppKey,0,$this->IV)
        
        );  
        }else{
            return array("status"=>"wrong username or password");
        }
    }
    
    
    
    
    
    public function initialize($dbHost,$dbUsername,$dbPassword,$dbName,$loginTable,$idCol,$passCol){
        $this->DB_host = $dbHost; 
        $this->DB_username = $dbUsername;
        $this->DB_password = $dbPassword;
        $this->DBName = $dbName;
        $this->loginTable = $loginTable;
        $this->IDcollumn = $idCol;
        $this->passwordCollumn = $passCol;
    }

    public function RBACisTokenAllowed(string $token, array $allowedRole){
       
        foreach($allowedRole as $ar){
            if($ar == $this->RBACgetTokenDetail($token)["role"]){
                return true;
            }else{
                return false;
            }
        }
    }



}

?>