<%@page import="generateVerify.CAImplementation"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Failure to authenticate</title>
<script>
function redirect(){
	window.location = "MakeRequest.jsp";
}

</script>
</head>
<body>
<h3>Sorry the page is not verified. Try again!</h3>
<input type="button" value="Retry" onclick="redirect()">
</body>
</html>