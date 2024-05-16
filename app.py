from flask import Flask, render_template, make_response, request, jsonify
from ml_model import extract_features, predict_phishing
import re

app = Flask(__name__)

# Dummy statistics data (replace with your actual statistics)
model_statistics = {
    'accuracy': 0.85,
    'precision': 0.82,
    'recall': 0.88,
    'f1_score': 0.85,
    # Add more statistics as needed
}

# Input validation for domain
def validate_domain(domain):
    # Define validation rules
    domain_regex = r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'  # Basic regex for domain validation
    
    # Validate domain against regex
    if re.match(domain_regex, domain):
        return True
    else:
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.form
        domain = data.get('domain')  # Get domain from form data
        
        # Validate domain input
        if validate_domain(domain):
            # Perform further processing if domain is valid
            features_df = extract_features(domain)  # Assuming extract_features function is defined elsewhere
            result = predict_phishing(features_df)  # Assuming predict_phishing function is defined elsewhere
            
            # Return the prediction result
            return jsonify({'result': result})
        else:
            return jsonify({'error': 'Invalid domain format'}), 400
    else:
        # Create a response object with the content you want to return
        response = make_response(render_template('index.html', statistics=model_statistics))
        
        # Set an HTTP-only cookie named 'session_id' with the value '123'
        response.set_cookie('session_id', '123', httponly=True)
        
        # Return the response object
        return response
    
@app.route('/statistics')
def statistics():
    return render_template('statistics.html', statistics=model_statistics)

if __name__ == '__main__':
    app.run(debug=True)
