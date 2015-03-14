package verification;

import generateVerify.CAImplementation;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class LoginServlet
 */

public class CSRServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	protected HttpServletRequest request;
	protected HttpServletResponse response;

	public CSRServlet(){
		super();
	}
	
	public void destroy() {
		super.destroy(); // Just puts "destroy" string in log
		// Put your code here
	}
	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, java.io.IOException {
		this.request = request;
		this.response = response;
		PrintWriter out = response.getWriter();
		try {
			
			UserBean user = new UserBean();
			user.setCName(request.getParameter("cname"));
			user.setBName(request.getParameter("bname"));
			user.setCity(request.getParameter("city"));
			user.setState(request.getParameter("state"));
			user.setCountry(request.getParameter("country"));
			user.setOrganization(request.getParameter("organization"));
			user.setEmail(request.getParameter("email"));
			//response.getOutputStream().write("hey got values");
			
			CAImplementation.generateRoot("www.RootCA.com", "Bloomington", "NetSecB649",
					"GraduateStudents", "Indiana", "US", "rootCA@trust.com");
			CAImplementation.generateIntermediate("issuer.com", "kol", "IU", "IU-Unit", "IN0", "US",
					"bbbb@gmail.com");

			String CN = "issuer.com";
			
			HashMap<X509Certificate, PrivateKey> inner = new HashMap<X509Certificate, PrivateKey>();
			for (String inter : CAImplementation.certificateMap.keySet()) {
				if (inter.equalsIgnoreCase(CN)) {
					inner = CAImplementation.certificateMap.get(inter);
					for (X509Certificate certs : inner.keySet()) {
						CAImplementation.certificate = certs;
					}
				}

			}
			out.println("The Certificate is generated");
			out.println("=================================================================");
			out.print(CAImplementation.generateClient(CAImplementation.certificate, user.getCname(), user.getCity(), user.getOrganization(),
					"Unit", user.getState(), user.getCountry(),user.getEmail()));
			
			System.out
			.println("####################################################################################");
	System.out
			.println("####################################################################################");

	
		
			/*out.println("Calling");
			out.println(CAImplementation.certificateMap.size());*/
			
			//response.sendRedirect("MakeRequest.jsp");

		}

		catch (Throwable theException) {
			System.out.println(theException);
		}

	}
	

}
