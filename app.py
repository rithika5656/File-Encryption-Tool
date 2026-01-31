import os
import secrets
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, after_this_request
from werkzeug.utils import secure_filename
from encryption import encrypt_file, decrypt_file

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DOWNLOAD_FOLDER'] = 'downloads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max limit

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
        
    if not password:
        flash('Password is required')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        
        try:
            # Output path logic
            output_path = encrypt_file(input_path, password)
            
            # Move to download folder for easier serving
            final_filename = os.path.basename(output_path)
            final_path = os.path.join(app.config['DOWNLOAD_FOLDER'], final_filename)
            
            # If encrypt_file saved it elsewhere, move it. 
            # Looking at existing encryption.py, it saves next to input file.
            # So output_path is likely in UPLOAD_FOLDER.
            os.rename(output_path, final_path)
            
            # Cleanup input file
            os.remove(input_path)
            
            return render_template('index.html', success=True, filename=final_filename, action='Encrypted')
            
        except Exception as e:
            flash(f"Error: {str(e)}")
            if os.path.exists(input_path):
                os.remove(input_path)
            return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
        
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
        
    if not password:
        flash('Password is required')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        
        try:
            # Determine output filename (remove .encrypted or add .decrypted)
            if filename.endswith('.encrypted'):
                output_filename = filename[:-10]
            else:
                output_filename = filename + '.decrypted'
                
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
            
            decrypt_file(input_path, password, output_path)
            
            # Move to download folder
            final_path = os.path.join(app.config['DOWNLOAD_FOLDER'], output_filename)
            if os.path.exists(final_path):
                os.remove(final_path) # Overwrite existing in downloads
            os.rename(output_path, final_path)
            
            # Cleanup input
            os.remove(input_path)
            
            return render_template('index.html', success=True, filename=output_filename, action='Decrypted')
            
        except Exception as e:
            flash(f"Error: {str(e)}")
            if os.path.exists(input_path):
                os.remove(input_path)
            return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
    
    @after_this_request
    def remove_file(response):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
        return response
        
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
