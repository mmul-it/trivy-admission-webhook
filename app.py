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
                "-f",
                "json",
                "-s",
                "CRITICAL",
                "--exit-code",
                "1",
                each_image["image"],
            ]
            if os.environ.get('ALLOW_INSECURE_REGISTRIES', "False").lower() == 'true':
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
        'server.socket_host': '0.0.0.0',
        'server.socket_port':443,
 
        'server.ssl_module':'pyopenssl',
        'server.ssl_certificate':'/certs/tls.crt',
        'server.ssl_private_key':'/certs/tls.key',
   }

cherrypy.config.update(server_config)
cherrypy.quickstart(admission_webhook())
