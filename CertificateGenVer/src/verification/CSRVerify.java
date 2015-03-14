package verification;

import generateVerify.CAImplementation;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import utils.CertificateNotFoundException;
import utils.CertificateRootFound;
import utils.CertificateVerificationException;

/**
 * Servlet implementation class CSRVerify
 */

public class CSRVerify extends HttpServlet {
	private static final long serialVersionUID = 1L;
	protected HttpServletRequest request;
	protected HttpServletResponse response;
	

	public CSRVerify() {
		super();

	}

	@SuppressWarnings("unused")
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		this.request = request;
		this.response = response;
		boolean res = false;
		PrintWriter out=response.getWriter();
		try {
			String domainReq=(request.getParameter("domainRequest"));
		/*out.print("heyy");
			
			out.println("verify"+CAImplementation.verifyCert(domainReq));*/
			//out.println("map"+CAImplementation.certificateMap);
			//out.println(domainReq);
			res = CAImplementation.verifyCert(domainReq);
				if(res){
				response.sendRedirect("Success.jsp");
				}
			else{
				response.sendRedirect("Failure.jsp");
				
				res= false;
		
		}
		}
		catch(CertificateVerificationException e){
			//out.print(e);
			response.sendRedirect("Failure.jsp");
		}
		catch(CertificateNotFoundException e){
			response.sendRedirect("Failure.jsp");
		
		}
		catch(CertificateRootFound e){
			response.sendRedirect("rootError.jsp");
		}
		catch (Throwable theException) {
			System.out.println(theException);
		}
		
	}

	
}
