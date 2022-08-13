from flask import Flask
from flask import request
from flask import render_template
import whois

app = Flask(__name__)

@app.route("/", methods=['POST','GET'])

def index():
    if request.method == "POST":
        domain = request.form['domain']
        if domain == "":
            return render_template("index.html")

        try:
            get_info = whois.whois(domain)
            dat = get_info
        except Exception as e:
            print(e)

        return render_template("index.html",data=dat)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
