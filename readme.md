###  bASTION Host 

- It allows you to access  into your network through your machine
- It is now old school normally you would use a vpn but for this case , they are not cheap so decided touse this
- So it will be publicly available but will only allow only our instance to access it 
- So you make it public but the res of your infrastructure will be private so you will store all the ssh keys in the bASTION hOST , so that you can access yournetwork through the Bastion Host
- This BASTION hOST CAN BE AUTOMATED INTO YOUR ENviroment and it can have all the ssh  keys set up , all you have to do is to give access to your devs only , they dont need access to anythibg else , you just give them acces sto the bastion  and they get access through that host 
- VPN are nicer  because they directly dropp you into the network and you dont have to connect anything else 

### sECURITY GROUPS
-thEE ARE LIKE FIREWALLS THEY DETERMINE Ie have rules on what gets in and what goes out of a subent
- rather that creating rules always we just made sure nothing enters databse and elastic search   expect private subents , this is better in terms of mentainance

### Variables 
eVEN OF WE DEFINE VARIABLES IN A FOLDER ABOVE WHEN WE WANT TO USE THEM WE HAVE TO REDIFINETHE,

### oUTPUTS
- THESE allow us to get variable ie `output "private_security_group" {
  value = module.security_group_private.security_group_id`    this allows us to use it in other modules 

###  




