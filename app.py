from subprocess import Popen
from flask import Flask, request, jsonify

admission_controller = Flask(__name__)

@admission_controller.route("/validate", methods=["POST"])
def deployment_webhook():
    request_info = request.get_json()
    uid = request_info["request"]["uid"]
    is_secure = True
    for each_image in request_info["request"]["object"]["spec"]["containers"]:
        command = [
            "/usr/local/bin/trivy",
            "image",
            "-f",
            "json",
            "-s",
            "CRITICAL",
            "--exit-code",
            "1",
            each_image["image"],
        ]
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
    return jsonify(msg)


if __name__ == "__main__":
    admission_controller.run(
        host="0.0.0.0", port=443, ssl_context=("certs/server.crt", "certs/server.key" ), debug=True
    )
