import os
import cherrypy
from subprocess import Popen

class admission_webhook:
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def validate(self, **keywords):
        request_info = cherrypy.request.json
        uid = request_info["request"]["uid"]
        is_secure = True
        for each_image in request_info["request"]["object"]["spec"]["containers"]:
            command = [
                "trivy",
                "image",
                "--format",
                "json",
                "--severity",
                os.environ.get("TRIVY_WEBHOOK_SEVERITY", "CRITICAL"),
                "--exit-code",
                "1",
                each_image["image"],
            ]
            if os.environ.get("TRIVY_WEBHOOK_ALLOW_INSECURE_REGISTRIES", "False").lower() == "true":
                command.insert(-1, "--insecure")
            print("Running command: %s" % " ".join(command))
            r = Popen(command)
            r.communicate()
            if r.returncode == 1:
                is_secure = False
    
        if is_secure:
            return admission_response(True, "All containers are secure", uid)
        return admission_response(False, "Not all containers secure, failing ...", uid)

def admission_response(allowed, message, uid):
    msg = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {"uid": uid, "allowed": allowed, "status": {"message": message}},
    }
    return msg

if __name__ == "__main__":
    server_config={
        "server.socket_host": os.environ.get("TRIVY_WEBHOOK_SSL_IP", "0.0.0.0"),
        "server.socket_port": int(os.environ.get("TRIVY_WEBHOOK_SSL_PORT", "443")),
 
        "server.ssl_module": "pyopenssl",
        "server.ssl_certificate": os.environ.get("TRIVY_WEBHOOK_SSL_CERT", "/certs/tls.crt"),
        "server.ssl_private_key": os.environ.get("TRIVY_WEBHOOK_SSL_KEY", "/certs/tls.key"),
   }

cherrypy.config.update(server_config)
cherrypy.quickstart(admission_webhook())
