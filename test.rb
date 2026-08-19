# brakeman_test_fixture.rb
#
# Intentionally vulnerable Rails controller for testing Brakeman detection.
# DO NOT deploy this code anywhere. It exists solely as a static-analysis
# test fixture for SecurEye's Brakeman scanner integration.
#
# Each method below maps to a known Brakeman check. Comments note the
# expected warning type so scan output can be validated against it.

class VulnerableController < ApplicationController
  skip_before_action :verify_authenticity_token

  # --- SQL Injection (CWE-89) ---
  # Brakeman check: SQL Injection
  def find_user
    name = params[:name]
    User.where("name = '#{name}'")
  end

  def find_user_raw
    User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
  end

  # --- Command Injection (CWE-78) ---
  # Brakeman check: Command Injection
  def ping_host
    host = params[:host]
    `ping -c 1 #{host}`
  end

  def run_backup
    system("tar -czf /tmp/backup.tar.gz #{params[:path]}")
  end

  # --- Mass Assignment (CWE-915) ---
  # Brakeman check: Mass Assignment
  def create_admin
    user = User.new(params[:user])
    user.save
  end

  # --- Cross-Site Scripting via raw/html_safe (CWE-79) ---
  # Brakeman check: Cross-Site Scripting
  def show_comment
    render inline: "<div>#{params[:comment].html_safe}</div>"
  end

  # --- Unsafe Deserialization (CWE-502) ---
  # Brakeman check: Remote Code Execution / Dangerous Eval
  def load_preferences
    prefs = Marshal.load(Base64.decode64(params[:prefs]))
    prefs
  end

  # --- Dynamic eval / code execution (CWE-95) ---
  # Brakeman check: Dangerous Eval
  def calculate
    eval(params[:formula])
  end

  # --- Insecure file access / path traversal (CWE-22) ---
  # Brakeman check: File Access
  def read_file
    filename = params[:filename]
    File.read("/var/data/#{filename}")
  end

  # --- Open redirect (CWE-601) ---
  # Brakeman check: Redirect
  def go_to
    redirect_to params[:url]
  end

  # --- Hardcoded credentials (CWE-798) ---
  # Brakeman check: Hardcoded secret / Attribute Restriction
  API_KEY = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxx"
  DB_PASSWORD = "SuperSecret123!"

  # --- SSRF via unvalidated URL (CWE-918) ---
  # Brakeman check: SSRF
  def fetch_remote
    uri = URI.parse(params[:url])
    Net::HTTP.get(uri)
  end

  # --- Weak cryptography (CWE-327) ---
  # Brakeman check: Weak Hash
  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end

  # --- Insecure cookie / session handling ---
  # Brakeman check: Session Settings
  def set_flag
    cookies[:admin] = { value: "true", secure: false, httponly: false }
  end
end
