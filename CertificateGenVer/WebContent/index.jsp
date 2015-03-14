<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>CSR</title>
<script>
function validate(){
	var emailId=document.forms["form"]["email"].value;
	var atpos=emailId.indexOf("@");
	var dotpos=emailId.lastIndexOf(".");
	var compname=document.forms["form"]["cname"].value;
	

/*       else if(((compname.contains("www") && compname.contains(".")))){
          alert("Company name not in valid format");
          return false;
       }  
 */
	  if(compname=="" || compname==null)
      {
     alert("Common Name cannot be left blank");
     return false;
      }
      if((compname.indexOf("www")==-1) || (compname.indexOf(".")==-1)){
			alert("Not a valid common name");
			return false;
		}
      if (atpos<1 || dotpos<atpos+2 || dotpos+2>=emailId.length)
	  {
	  alert("Not a valid e-mail address");
	  return false;
	  }
	  else if(emailId ==""||emailId ==null)
	  {
	   alert("Enter the emailId in the correct format");
	   return false;	 	
	   }
	else{
			return true;
          } 
          
}
</script>
</head>

<body bgcolor="skyblue" background="./resources/yellowbg.jpg">

	<div
		style="opacity: 0.4; position: relative; background-color: #40B3DF">
		<h2 style="text-align: center">
			<font color="black">Form Request details</font>
		</h2>

	</div>


	<form action="register" name="form" method="GET"
		onsubmit="return validate()">
		<br>
		<table align="center">
			<tr>
				<td>Common Name:<font color="red">*</font>
				<td><input type="text" name="cname" value="">
			</tr>
			<tr>
				<td>Business Name:
				<td><input type="text" name="bname">
			</tr>
			<tr>
				<td>City:
				<td><input type="text" name="city">
			</tr>
			<tr>
				<td>State:
				<td><input type="text" name="state">
			</tr>
			<tr>
				<td>Country:
				<td><input type="text" name="country" maxlength="2">
			</tr>
			<tr>
				<td>Organizational Unit:
				<td><input type="text" name="dname">
			</tr>
			<tr>
				<td>Email-address<font color="red">*</font>:
				<td><input type="text" name="email" value="">
			</tr>
		</table>
		<center>
			<input type="submit" value="Submit">
		</center>
	</form>

</body>
</html>