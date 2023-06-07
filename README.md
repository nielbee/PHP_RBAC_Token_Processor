# PHP_RBAC_Token_Processor
A simple set of tool to generate role based Access Control. Suitable to secure your API Endpoint by limiting set of role that allowed to access it
  
## How to use :
### change setting
change secret app key with with your own  
cipher method and IV byte is not neccessary  
by default it use mysql driver, but you can change this as well


### intialize by using method `initialize(params)`  
this method is used to setup database connection by providing database host, username, password and name. also to use RBAC feature, you must set users equivalent table and its ID and password field  
### get personal user token by using method `RBACmake_token_for(params)` 
provide username and password and ot will look through users equivalent table. it will returning array with token if it found data with provided username and token

### securing Endpoint by using method `RBACis_token_allowed(params)`
provide token and array of allowed role on this method. it will returning boolean true if that user role is allowed  

### get ID with token by using method `RBACget_token_detail(params)`
no need to pass ID when accessing endpoint, just provide API on this method paramater, it will return array of user ID
## database consideration
need a `role` field in users (or equivalent table) 
