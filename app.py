import os
from flask import Flask, render_template, request, redirect, session, url_for, make_response, jsonify, abort
import io, csv
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore
from flask_wtf import CSRFProtect
import anthropic
app = Flask(__name__)
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    raise RuntimeError('SECRET_KEY environment variable is required')
app.secret_key = secret_key
csrf = CSRFProtect(app)
# Initialize Firebase Admin SDK
if not firebase_admin._apps:
   cred = credentials.Certificate("/etc/secrets/serviceAccountKey.json")
firebase_admin.initialize_app(cred)

db = firestore.client()


@firestore.transactional
def _increment_patient_counter(transaction):
    """Atomically increments the patient counter and returns the new value."""
    counter_ref = db.collection("counters").document("patient_id")
    snapshot = counter_ref.get(transaction=transaction)
    last = snapshot.get("last") if snapshot.exists else 0
    new_last = last + 1
    transaction.set(counter_ref, {"last": new_last})
    return new_last


DEBUG_AI = os.getenv("AI_DEBUG", "False").lower() in ("1", "true", "yes")
client = anthropic.Anthropic(api_key=os.getenv("CLAUDE_API_KEY"))

def call_claude(prompt):
    """Calls Claude AI with the given prompt and returns the response."""
    try:
        response = client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        if DEBUG_AI:
            return f"AI Error: {str(e)}"
        else:
            return "AI service is temporarily unavailable. Please try again later."



def log_action(user_id, action, details=None):
    db.collection('audit_logs').add({
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': firestore.SERVER_TIMESTAMP
    })




def get_patient_or_404(patient_id):
    """Retrieve patient document and verify current user access."""
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)
    if not patient_doc:
        abort(404, description="Patient not found.")

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session.get('user_id'):
        abort(403, description="Access denied.")

    return patient


def login_required(approved_only=True):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')
            if approved_only and session.get('is_admin') != 1 and session.get('approved') == 0:
                return "Access denied. Awaiting approval by admin."
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = None
        is_admin = 0
        approved = 1
        active = 1  # New users are active by default

        # Check if email or phone exists
        existing = db.collection('users') \
                     .where('email', '==', email) \
                     .stream()
        existing_phone = db.collection('users') \
                           .where('phone', '==', phone) \
                           .stream()

        if any(existing) or any(existing_phone):
            return "Email or phone number already registered."

        user_data = {
            'name': name,
            'email': email,
            'password': password,
            'phone': phone,
            'is_admin': is_admin,
            'institute': institute,
            'approved': approved,
            'active': active
        }

        user_ref = db.collection('users').add(user_data)
        log_action(user_id=None, action="Register", details=f"{name} registered as Individual Physio")

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        users = db.collection('users').where('email', '==', email).stream()
        user_doc = next(users, None)

        if not user_doc:
            return "Invalid login credentials."

        user = user_doc.to_dict()
        user['id'] = user_doc.id  # Store document ID

        if check_password_hash(user['password'], password_input):
            if user.get('approved') == 1 and user.get('active') == 1:
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['institute'] = user.get('institute')
                session['is_admin'] = user['is_admin']
                session['approved'] = user['approved']
                log_action(user['id'], "Login", f"{user['name']} logged in.")
                return redirect('/dashboard')
            elif user.get('active') == 0:
                return "Your account has been deactivated. Contact your admin."
            else:
                return "Your registration is pending admin approval."
        else:
            return "Invalid login credentials."

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
@login_required()
def dashboard():
    return render_template('dashboard.html', name=session['user_name'])

@app.route('/admin_dashboard')
@login_required()
def admin_dashboard():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/login_institute')

    # Fetch pending users from the same institute
    users = db.collection('users') \
              .where('is_admin', '==', 0) \
              .where('approved', '==', 0) \
              .where('institute', '==', session['institute']) \
              .stream()

    pending_physios = [dict(user.to_dict(), id=user.id) for user in users]

    return render_template(
        'admin_dashboard.html',
        pending_physios=pending_physios,
        name=session['user_name'],
        institute=session['institute']
    )

@app.route('/dashboard_data', methods=['POST'])
@login_required()
def dashboard_data():
    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    user_doc = db.collection('users').document(user_id).get()

    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404

    user = user_doc.to_dict()
    name = user.get('name')
    is_admin = user.get('is_admin', 0)

    patients = db.collection('patients').where('physio_id', '==', user_id).stream()
    patient_list = [p.to_dict() for p in patients]

    return jsonify({
        "name": name,
        "is_admin": is_admin,
        "patients": patient_list
    })



@app.route('/view_patients')
@login_required()
def view_patients():
    query = db.collection('patients')
    
    name_filter = request.args.get('name')
    id_filter = request.args.get('patient_id')

    # Filter for admin or individual physio
    if session.get('is_admin') == 1:
        # Admin: only see patients from same institute
        physios = db.collection('users') \
                    .where('institute', '==', session['institute']) \
                    .stream()
        physio_ids = [p.id for p in physios]
        patients = []
        for pid in physio_ids:
            patients += [p for p in query.where('physio_id', '==', pid).stream()]
    else:
        # Regular physio: see their own patients
        patients = query.where('physio_id', '==', session['user_id']).stream()

    # Apply filters in-memory
    results = []
    for p in patients:
        data = p.to_dict()
        data['id'] = p.id
        if name_filter and name_filter.lower() not in data.get('name', '').lower():
            continue
        if id_filter and id_filter.lower() not in data.get('patient_id', '').lower():
            continue
        results.append(data)

    return render_template('view_patients.html', patients=results)

@app.route('/register_institute', methods=['GET', 'POST'])
def register_institute():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = request.form['institute']
        is_admin = 1
        approved = 1
        active = 1

        # Check for duplicate email or phone
        existing = db.collection('users').where('email', '==', email).stream()
        existing_phone = db.collection('users').where('phone', '==', phone).stream()

        if any(existing) or any(existing_phone):
            return "Email or phone number already registered."

        db.collection('users').add({
            'name': name,
            'email': email,
            'phone': phone,
            'password': password,
            'institute': institute,
            'is_admin': is_admin,
            'approved': approved,
            'active': active
        })

        log_action(user_id=None, action="Register", details=f"{name} registered as Institute Admin")
        return redirect('/login_institute')

    return render_template('register_institute.html')

@app.route('/login_institute', methods=['GET', 'POST'])
def login_institute():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        users = db.collection('users').where('email', '==', email).stream()
        user_doc = next(users, None)

        if not user_doc:
            return "Invalid credentials or account doesn't exist."

        user = user_doc.to_dict()
        user['id'] = user_doc.id

        if not check_password_hash(user['password'], password_input):
            return "Invalid credentials or account doesn't exist."

        if user.get('approved') == 0:
            return "Your account is pending approval by the institute admin."

        if user.get('active') == 0:
            return "Your account has been deactivated. Please contact your admin."

        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['institute'] = user.get('institute')
        session['is_admin'] = user['is_admin']
        session['approved'] = user['approved']

        log_action(user['id'], "Login", f"{user['name']} (Admin: {user['is_admin']}) logged in.")

        return redirect('/admin_dashboard' if user['is_admin'] == 1 else '/dashboard')

    return render_template('login_institute.html')



@app.route('/approve_physios')
@login_required()
def approve_physios():
    if session.get('is_admin') != 1:
        return redirect('/login_institute')

    users = db.collection('users') \
              .where('is_admin', '==', 0) \
              .where('approved', '==', 0) \
              .where('institute', '==', session['institute']) \
              .stream()

    physios = [dict(u.to_dict(), id=u.id) for u in users]

    return render_template('approve_physios.html', physios=physios)

@app.route('/audit_logs')
@login_required()
def audit_logs():
    logs = []

    if session.get('is_admin') == 1:
        # Admin: fetch logs for all users in their institute
        users = db.collection('users') \
                  .where('institute', '==', session['institute']) \
                  .stream()
        user_map = {u.id: u.to_dict() for u in users}
        user_ids = list(user_map.keys())

        for uid in user_ids:
            entries = db.collection('audit_logs').where('user_id', '==', uid).stream()
            for e in entries:
                data = e.to_dict()
                data['name'] = user_map[uid]['name']
                logs.append(data)

    elif session.get('is_admin') == 0:
        # Individual physio: only their logs
        entries = db.collection('audit_logs').where('user_id', '==', session['user_id']).stream()
        for e in entries:
            data = e.to_dict()
            data['name'] = session['user_name']
            logs.append(data)

    # Sort by timestamp descending
    logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    return render_template('audit_logs.html', logs=logs)

@app.route('/export_audit_logs')
@login_required()
def export_audit_logs():
    if session.get('is_admin') != 1:
        return redirect('/login_institute')

    users = db.collection('users') \
              .where('institute', '==', session['institute']) \
              .stream()
    user_map = {u.id: u.to_dict() for u in users}
    user_ids = list(user_map.keys())

    logs = []
    for uid in user_ids:
        entries = db.collection('audit_logs').where('user_id', '==', uid).stream()
        for e in entries:
            log = e.to_dict()
            logs.append([
                user_map[uid]['name'],
                log.get('action', ''),
                log.get('details', ''),
                log.get('timestamp', '')
            ])

    # Prepare CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['User', 'Action', 'Details', 'Timestamp'])
    writer.writerows(logs)

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response


@app.route('/reject_user/<user_id>', methods=['POST'])
@login_required()
def reject_user(user_id):
    if session.get('is_admin') != 1:
        return "Unauthorized", 403

    # Check the user document
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return "User not found", 404

    user_data = user_doc.to_dict()
    if user_data.get('approved') == 0:
        user_ref.delete()
        log_action(
            user_id=session['user_id'],
            action="Reject User",
            details=f"Rejected user {user_data.get('name')} (Email: {user_data.get('email')})"
        )

    return redirect('/approve_physios')

@app.route('/register_with_institute', methods=['GET', 'POST'])
def register_with_institute():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = request.form['institute']
        is_admin = 0
        approved = 0
        active = 1

        # Check if user already exists
        existing_email = db.collection('users').where('email', '==', email).stream()
        existing_phone = db.collection('users').where('phone', '==', phone).stream()

        if any(existing_email) or any(existing_phone):
            return "Email or phone number already registered."

        # Register new user under selected institute
        db.collection('users').add({
            'name': name,
            'email': email,
            'phone': phone,
            'password': password,
            'institute': institute,
            'is_admin': is_admin,
            'approved': approved,
            'active': active
        })

        log_action(user_id=None, action="Register", details=f"{name} registered as Institute Physio (pending approval)")

        return "Registration successful! Awaiting admin approval."

    # GET method: show list of institutes (unique from admin users)
    admins = db.collection('users').where('is_admin', '==', 1).stream()
    institutes = list({admin.to_dict().get('institute') for admin in admins})

    return render_template('register_with_institute.html', institutes=institutes)

@app.route('/approve_user/<user_id>', methods=['POST'])
@login_required()
def approve_user(user_id):
    if session.get('is_admin') != 1:
        return redirect('/login_institute')

    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return "User not found", 404

    user = user_doc.to_dict()

    # Approve the user
    user_ref.update({'approved': 1})

    # Log the action
    log_action(
        user_id=session['user_id'],
        action="Approve User",
        details=f"Approved user {user.get('name')} (Email: {user.get('email')})"
    )

    return redirect('/approve_physios')

@app.route('/manage_users')
@login_required()
def manage_users():
    if session.get('is_admin') != 1:
        return "Access Denied: Admins only."

    users = db.collection('users') \
              .where('is_admin', '==', 0) \
              .where('approved', '==', 1) \
              .where('institute', '==', session['institute']) \
              .stream()

    user_list = [dict(u.to_dict(), id=u.id) for u in users]

    return render_template('manage_users.html', users=user_list)

@app.route('/deactivate_user/<user_id>', methods=['POST'])
@login_required()
def deactivate_user(user_id):
    if session.get('is_admin') != 1:
        return "Access Denied"

    db.collection('users').document(user_id).update({'active': 0})

    log_action(
        user_id=session['user_id'],
        action="Deactivate User",
        details=f"User ID {user_id} was deactivated"
    )

    return redirect('/manage_users')

@app.route('/reactivate_user/<user_id>', methods=['POST'])
@login_required()
def reactivate_user(user_id):
    if session.get('is_admin') != 1:
        return "Access Denied"

    db.collection('users').document(user_id).update({'active': 1})

    log_action(
        user_id=session['user_id'],
        action="Reactivate User",
        details=f"User ID {user_id} was reactivated"
    )

    return redirect('/manage_users')


# Patient Data Entry Routes (clinical reasoning flow)
@app.route('/add_patient', methods=['GET', 'POST'])
@login_required()
def add_patient():
    if request.method == 'POST':
        name = request.form['name']
        age_sex = request.form['age_sex']
        contact = request.form['contact']
        present_history = request.form['present_history']
        past_history = request.form['past_history']

        @firestore.transactional
        def txn_add_patient(transaction):
            new_num = _increment_patient_counter(transaction)
            new_id = f"PAT-{new_num:03d}"
            patient_ref = db.collection('patients').document()
            transaction.set(patient_ref, {
                'physio_id': session['user_id'],
                'patient_id': new_id,
                'name': name,
                'age_sex': age_sex,
                'contact': contact,
                'present_history': present_history,
                'past_history': past_history,
                'created_at': firestore.SERVER_TIMESTAMP
            })
            return new_id

        transaction = db.transaction()
        new_id = txn_add_patient(transaction)

        log_action(
            user_id=session['user_id'],
            action="Add Patient",
            details=f"Added patient {name} (ID: {new_id})"
        )

        return redirect(f'/subjective/{new_id}')

    return render_template('add_patient.html')



@app.route('/subjective/<patient_id>', methods=['GET', 'POST'])
@login_required()
def subjective(patient_id):
    # Retrieve patient and ensure current user has access
    patient = get_patient_or_404(patient_id)

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'body_structure': request.form['body_structure'],
            'body_function': request.form['body_function'],
            'activity_performance': request.form['activity_performance'],
            'activity_capacity': request.form['activity_capacity'],
            'contextual_environmental': request.form['contextual_environmental'],
            'contextual_personal': request.form['contextual_personal']
        }

        db.collection('subjective_examination').add(data)

        return redirect(f'/perspectives/{patient_id}')

    return render_template('subjective.html', patient_id=patient_id)


@app.route('/perspectives/<patient_id>', methods=['GET', 'POST'])
@login_required()
def perspectives(patient_id):
    # Fetch patient by ID
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'knowledge': request.form['knowledge'],
            'attribution': request.form['attribution'],
            'illness_duration': request.form['illness_duration'],
            'consequences_awareness': request.form['consequences_awareness'],
            'locus_of_control': request.form['locus_of_control'],
            'affective_aspect': request.form['affective_aspect']
        }

        db.collection('patient_perspectives').add(data)

        return redirect(f'/initial_plan/{patient_id}')

    return render_template('perspectives.html', patient_id=patient_id)


@app.route('/initial_plan/<patient_id>', methods=['GET', 'POST'])
@login_required()
def initial_plan(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        fields = [
            'active_movements',
            'passive_movements',
            'passive_over_pressure',
            'resisted_movements',
            'combined_movements',
            'special_tests',
            'neuro_dynamic_examination'
        ]

        data = {'patient_id': patient_id}
        for field in fields:
            data[field] = request.form.get(field)
            data[field + '_details'] = request.form.get(field + '_details', '')

        db.collection('initial_plan').add(data)

        return redirect(f'/patho_mechanism/{patient_id}')

    return render_template('initial_plan.html', patient_id=patient_id)


@app.route('/patho_mechanism/<patient_id>', methods=['GET', 'POST'])
@login_required()
def patho_mechanism(patient_id):
    # Fetch patient and verify permissions
    patient = get_patient_or_404(patient_id)

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'area_involved': request.form['area_involved'],
            'presenting_symptom': request.form['presenting_symptom'],
            'pain_type': request.form['pain_type'],
            'pain_nature': request.form['pain_nature'],
            'pain_severity': request.form['pain_severity'],
            'pain_irritability': request.form['pain_irritability'],
            'symptom_source': request.form['symptom_source'],
            'tissue_healing_stage': request.form['tissue_healing_stage']
        }

        db.collection('patho_mechanism').add(data)

        return redirect(f'/chronic_disease/{patient_id}')

    return render_template('patho_mechanism.html', patient_id=patient_id)


@app.route('/chronic_disease/<patient_id>', methods=['GET', 'POST'])
@login_required()
def chronic_disease(patient_id):
    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'cause': request.form['cause'],
            'cause_detail': request.form.get('cause_detail', '')
        }

        db.collection('chronic_diseases').add(data)

        return redirect(f'/clinical_flags/{patient_id}')

    return render_template('chronic_disease.html', patient_id=patient_id)


@app.route('/clinical_flags/<patient_id>', methods=['GET', 'POST'])
@login_required()
def clinical_flags(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'red_flag': request.form['red_flag'],
            'orange_flag': request.form['orange_flag'],
            'yellow_flag': request.form['yellow_flag'],
            'black_flag': request.form['black_flag'],
            'blue_flag': request.form['blue_flag']
        }

        db.collection('clinical_flags').add(data)

        return redirect(f'/objective_assessment/{patient_id}')

    return render_template('clinical_flags.html', patient_id=patient_id)


@app.route('/objective_assessment/<patient_id>', methods=['GET', 'POST'])
@login_required()
def objective_assessment(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'plan': request.form['plan'],
            'plan_details': request.form.get('plan_details', '')
        }

        db.collection('objective_assessment').add(data)

        return redirect(f'/provisional_diagnosis/{patient_id}')

    return render_template('objective_assessment.html', patient_id=patient_id)


@app.route('/provisional_diagnosis/<patient_id>', methods=['GET', 'POST'])
@login_required()
def provisional_diagnosis(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'likelihood': request.form['likelihood'],
            'structure_fault': request.form['structure_fault'],
            'symptom': request.form['symptom'],
            'findings_support': request.form['findings_support'],
            'findings_reject': request.form['findings_reject'],
            'hypothesis_supported': request.form['hypothesis_supported']
        }

        db.collection('provisional_diagnosis').add(data)

        return redirect(f'/smart_goals/{patient_id}')

    return render_template('provisional_diagnosis.html', patient_id=patient_id)


@app.route('/smart_goals/<patient_id>', methods=['GET', 'POST'])
@login_required()
def smart_goals(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'patient_goal': request.form['patient_goal'],
            'baseline_status': request.form['baseline_status'],
            'measurable_outcome': request.form['measurable_outcome'],
            'time_duration': request.form['time_duration']
        }

        db.collection('smart_goals').add(data)

        return redirect(f'/treatment_plan/{patient_id}')

    return render_template('smart_goals.html', patient_id=patient_id)



@app.route('/treatment_plan/<patient_id>', methods=['GET', 'POST'])
@login_required()
def treatment_plan(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'treatment_plan': request.form['treatment_plan'],
            'goal_targeted': request.form['goal_targeted'],
            'reasoning': request.form['reasoning'],
            'reference': request.form['reference']
        }

        db.collection('treatment_plan').add(data)

        return redirect('/dashboard')

    return render_template('treatment_plan.html', patient_id=patient_id)



@app.route('/follow_up_new/<patient_id>', methods=['GET', 'POST'])
@login_required()
def follow_up_new(patient_id):
    # Fetch patient and verify permissions
    patient = get_patient_or_404(patient_id)

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'session_number': request.form['session_number'],
            'session_date': request.form['session_date'],
            'grade': request.form['grade'],
            'belief_treatment': request.form['belief_treatment'],
            'belief_feedback': request.form['belief_feedback'],
            'treatment_plan': request.form['treatment_plan']
        }

        db.collection('follow_ups').add(data)

        return redirect(f'/view_follow_ups/{patient_id}')

    return render_template('follow_up_new.html', patient_id=patient_id)

@app.route('/view_follow_ups/<patient_id>')
@login_required()
def view_follow_ups(patient_id):
        patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
        patient_doc = next(patients, None)

        if not patient_doc:
            return "Patient not found."

        patient = patient_doc.to_dict()
        if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
            return "Access denied."

        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.DESCENDING) \
                      .stream()

        followup_list = [f.to_dict() for f in followups]

        return render_template('view_follow_ups.html', patient_id=patient_id, followups=followup_list)

    

@app.route('/patient_report/<patient_id>')
@login_required()
def patient_report(patient_id):
    # Fetch patient
    patient_docs = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patient_docs, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        return "Access denied."

    def fetch_one(collection):
        docs = db.collection(collection).where('patient_id', '==', patient_id).stream()
        for d in docs:
            return d.to_dict()
        return None

    return render_template(
        'patient_report.html',
        patient=patient,
        subjective=fetch_one('subjective_examination'),
        perspectives=fetch_one('patient_perspectives'),
        diagnosis=fetch_one('provisional_diagnosis'),
        goals=fetch_one('smart_goals'),
        treatment=fetch_one('treatment_plan')
    )


@app.route('/download_report/<patient_id>')
@login_required()
def download_report(patient_id):
        # Fetch patient and clinical data
        patient_docs = db.collection('patients').where('patient_id', '==', patient_id).stream()
        patient_doc = next(patient_docs, None)

        if not patient_doc:
            return "Patient not found."

        patient = patient_doc.to_dict()
        if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
            return "Access denied."

        def fetch_one(collection):
            docs = db.collection(collection).where('patient_id', '==', patient_id).stream()
            for d in docs:
                return d.to_dict()
            return None

        rendered = render_template(
            'patient_report.html',
            patient=patient,
            subjective=fetch_one('subjective_examination'),
            perspectives=fetch_one('patient_perspectives'),
            diagnosis=fetch_one('provisional_diagnosis'),
            goals=fetch_one('smart_goals'),
            treatment=fetch_one('treatment_plan')
        )

        from weasyprint import HTML
        pdf = HTML(string=rendered).write_pdf()

        log_action(
            user_id=session['user_id'],
            action="Download Report",
            details=f"Downloaded PDF report for patient {patient_id}"
        )

        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={patient_id}_report.pdf'
        return response

   



@app.route('/edit_patient/<patient_id>', methods=['GET', 'POST'])
@login_required()
def edit_patient(patient_id):
    # Fetch patient doc
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    doc_id = patient_doc.id
    patient = patient_doc.to_dict()

    if session.get('is_admin') != 1 and patient['physio_id'] != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        name = request.form['name']
        age_sex = request.form['age_sex']
        contact = request.form['contact']

        db.collection('patients').document(doc_id).update({
            'name': name,
            'age_sex': age_sex,
            'contact': contact
        })

        log_action(
            user_id=session['user_id'],
            action="Edit Patient",
            details=f"Edited patient {patient_id}"
        )

        return redirect('/view_patients')

    return render_template('edit_patient.html', patient=patient)

# REPLACE your AI endpoints with these enhanced versions that collect cumulative data

def get_cumulative_patient_data(patient_id):
    """Helper function to collect ALL data from previous workflow steps"""
    data = {}
    
    # Basic patient info
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)
    if patient_doc:
        data['patient'] = patient_doc.to_dict()
    
    # Collect data from each workflow step
    collections = [
        'subjective_examination',
        'patient_perspectives', 
        'initial_plan',
        'patho_mechanism',
        'chronic_diseases',
        'clinical_flags',
        'objective_assessment',
        'provisional_diagnosis',
        'smart_goals',
        'treatment_plan'
    ]
    
    for collection in collections:
        docs = db.collection(collection).where('patient_id', '==', patient_id).stream()
        for doc in docs:
            data[collection] = doc.to_dict()
            break  # Get first/latest entry
    
    return data

# ENHANCED AI ENDPOINTS - Replace your existing ones with these:

@csrf.exempt
@app.route("/api/ai/subjective-exam", methods=["POST"])
@login_required()
def ai_subjective_exam():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL cumulative data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
You are assisting with ICF framework subjective examination.

Patient Information:
- Age/Sex: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

Based on this clinical information, suggest entries for these 6 ICF categories:
1. Impairment of body structure
2. Impairment of body function  
3. Activity Limitation - Performance
4. Activity Limitation - Capacity
5. Contextual Factors - Environmental
6. Contextual Factors - Personal

Provide single-line clinical statements for each section.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/patient-perspectives", methods=["POST"])
@login_required()
def ai_patient_perspectives():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get cumulative data including subjective examination
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Based on patient and subjective examination data, provide clinical suggestions for Patient Perspectives:

Patient Information:
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

Subjective Examination:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Issues: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}

Suggest for these Patient Perspective areas:
1. Knowledge of Illness
2. Illness Attribution
3. Expectation  
4. Awareness of Control
5. Locus of Control
6. Affective Aspect

Write each as a one-line clinical interpretation.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/initial-plan", methods=["POST"])
@login_required()
def ai_initial_plan():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get cumulative data from patient + subjective + perspectives
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Determine appropriate initial assessment plan based on cumulative clinical data:

Patient History:
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

Subjective Findings:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}

Patient Perspectives:
- Knowledge of Illness: {perspectives.get('knowledge', '')}
- Illness Attribution: {perspectives.get('attribution', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}

Based on this information, suggest:
1. Assessment priorities (Mandatory/Contraindicated/Precaution)
2. Movement testing recommendations (Active/Passive/Resisted)
3. Special considerations and precautions
4. Patient-specific modifications needed

Provide responses as concise bullet points.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/pathophysiological", methods=["POST"])
@login_required()
def ai_pathophysiological():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get cumulative data from all previous steps
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        
        prompt = f"""
Generate pathophysiological mechanism hypothesis based on comprehensive clinical data:

Patient History:
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

Clinical Findings:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Issues: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}

Assessment Plan:
- Movement Testing: {initial_plan.get('active_movements', '')}
- Special Tests: {initial_plan.get('special_tests', '')}

Patient Factors:
- Illness Attribution: {perspectives.get('attribution', '')}
- Affective Aspects: {perspectives.get('affective_aspect', '')}

Based on this comprehensive data, provide:
1. Most likely pathophysiological hypothesis
2. Clinical reasoning supporting this hypothesis  
3. Alternative mechanisms to consider
4. Recommendations for further assessment

Keep clinical and evidence-based.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/clinical-flags", methods=["POST"])
@login_required()
def ai_clinical_flags():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get comprehensive data from all previous steps
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Identify psychosocial and clinical flags based on comprehensive patient data:

Patient History:
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

Clinical Presentation:
- Body Function Issues: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Pain Characteristics: {patho.get('pain_type', '')} - {patho.get('pain_nature', '')}
- Pain Severity: {patho.get('pain_severity', '')}

Psychosocial Factors:
- Patient Knowledge: {perspectives.get('knowledge', '')}
- Illness Attribution: {perspectives.get('attribution', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}
- Affective Aspects: {perspectives.get('affective_aspect', '')}

Environmental Factors:
- Environmental Context: {subjective.get('contextual_environmental', '')}
- Personal Context: {subjective.get('contextual_personal', '')}

Based on this data, identify relevant flags:
- 🔴 Red Flags (Serious pathology indicators)
- 🟠 Orange Flags (Psychiatric/mental health concerns)
- 🟡 Yellow Flags (Psychosocial risk factors)
- ⚫ Black Flags (Occupational/compensation issues)
- 🔵 Blue Flags (Workplace/social environment factors)

Provide specific reasoning for each flag based on the clinical data.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/provisional-diagnosis", methods=["POST"])
@login_required()
def ai_provisional_diagnosis():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL previous clinical data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract all relevant data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho = all_data.get('patho_mechanism', {})
        chronic = all_data.get('chronic_diseases', {})
        flags = all_data.get('clinical_flags', {})
        objective = all_data.get('objective_assessment', {})
        
        prompt = f"""
Formulate provisional diagnosis based on comprehensive clinical reasoning:

SUBJECTIVE DATA:
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}

PATHOPHYSIOLOGY:
- Area Involved: {patho.get('area_involved', '')}
- Presenting Symptoms: {patho.get('presenting_symptom', '')}
- Pain Type: {patho.get('pain_type', '')}
- Pain Nature: {patho.get('pain_nature', '')}
- Pain Severity: {patho.get('pain_severity', '')}
- Tissue Healing Stage: {patho.get('tissue_healing_stage', '')}

PSYCHOSOCIAL FACTORS:
- Clinical Flags: Red: {flags.get('red_flag', '')}, Yellow: {flags.get('yellow_flag', '')}
- Patient Attribution: {perspectives.get('attribution', '')}

OBJECTIVE FINDINGS:
- Assessment Plan: {objective.get('plan', '')}
- Plan Details: {objective.get('plan_details', '')}

CHRONIC FACTORS:
- Contributing Causes: {chronic.get('cause', '')}

Based on this comprehensive clinical picture, provide:
1. Most likely provisional diagnosis with confidence level
2. Primary structure(s) at fault
3. Key symptoms supporting the diagnosis
4. Clinical findings that support this diagnosis
5. Findings that might contradict this diagnosis  
6. Overall assessment of whether hypothesis is supported

Format as structured clinical reasoning.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/smart-goals", methods=["POST"])
@login_required()
def ai_smart_goals():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get comprehensive clinical data for goal setting
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        patho = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Develop SMART Goals based on comprehensive clinical assessment:

PATIENT PRESENTATION:
- Age/Sex: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}

ACTIVITY LIMITATIONS:
- Performance Issues: {subjective.get('activity_performance', '')}
- Capacity Issues: {subjective.get('activity_capacity', '')}

PATIENT EXPECTATIONS:
- Patient Knowledge: {perspectives.get('knowledge', '')}
- Expectations: {perspectives.get('consequences_awareness', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}

CLINICAL DIAGNOSIS:
- Provisional Diagnosis: {diagnosis.get('structure_fault', '')} - {diagnosis.get('symptom', '')}
- Pain Severity: {patho.get('pain_severity', '')}
- Tissue Healing Stage: {patho.get('tissue_healing_stage', '')}

CONTEXTUAL FACTORS:
- Environmental: {subjective.get('contextual_environmental', '')}
- Personal: {subjective.get('contextual_personal', '')}

Based on this comprehensive assessment, develop SMART Goals:

1. SPECIFIC patient-centered goals addressing main functional limitations
2. MEASURABLE outcomes that can be objectively assessed
3. ACHIEVABLE goals considering patient factors and healing timeline
4. RELEVANT goals aligned with patient priorities and expectations
5. TIME-BOUND goals with realistic timeframes based on condition

Also suggest:
- Baseline status measurements to track from
- Key outcome measures to monitor progress
- Appropriate timeframes for goal achievement

Format as practical, patient-centered SMART goals.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/treatment-plan", methods=["POST"])
@login_required()
def ai_treatment_plan():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL clinical data for comprehensive treatment planning
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical picture
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho = all_data.get('patho_mechanism', {})
        chronic = all_data.get('chronic_diseases', {})
        flags = all_data.get('clinical_flags', {})
        objective = all_data.get('objective_assessment', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        goals = all_data.get('smart_goals', {})
        
        prompt = f"""
Develop comprehensive physiotherapy treatment plan based on complete clinical assessment:

CLINICAL DIAGNOSIS:
- Provisional Diagnosis: {diagnosis.get('structure_fault', '')} 
- Symptoms: {diagnosis.get('symptom', '')}
- Likelihood: {diagnosis.get('likelihood', '')}

PATHOPHYSIOLOGY:
- Area Involved: {patho.get('area_involved', '')}
- Pain Type/Nature: {patho.get('pain_type', '')} / {patho.get('pain_nature', '')}
- Pain Severity: {patho.get('pain_severity', '')}
- Tissue Healing Stage: {patho.get('tissue_healing_stage', '')}

FUNCTIONAL LIMITATIONS:
- Body Function Issues: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}

PATIENT FACTORS:
- Patient Goals: {goals.get('patient_goal', '')}
- Baseline Status: {goals.get('baseline_status', '')}
- Illness Attribution: {perspectives.get('attribution', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}

PSYCHOSOCIAL CONSIDERATIONS:
- Yellow Flags: {flags.get('yellow_flag', '')}
- Blue Flags: {flags.get('blue_flag', '')}
- Affective Aspects: {perspectives.get('affective_aspect', '')}

CHRONIC FACTORS:
- Contributing Causes: {chronic.get('cause', '')}

OBJECTIVE FINDINGS:
- Assessment Results: {objective.get('plan_details', '')}

Based on this comprehensive clinical picture, develop:

1. TREATMENT PLAN:
   - Phase-based approach aligned with tissue healing
   - Specific interventions targeting identified impairments
   - Manual therapy techniques if indicated
   - Exercise prescription addressing functional goals
   - Pain management strategies
   - Patient education components

2. GOALS TARGETED:
   - How treatment addresses specific SMART goals
   - Expected functional outcomes
   - Timeline for goal achievement

3. CLINICAL REASONING:
   - Evidence-based rationale for chosen interventions
   - How treatment addresses pathophysiology
   - Consideration of psychosocial factors
   - Modification strategies for patient factors

4. REFERENCES:
   - Current evidence supporting treatment approach
   - Clinical guidelines relevant to condition
   - Key research informing intervention choices

Format as a structured, evidence-based treatment plan ready for clinical implementation.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE FOLLOW-UP AI ENDPOINTS TO THE END OF YOUR APP.PY
# (After your clinical workflow AI endpoints, before if __name__ == '__main__':)

@csrf.exempt
@app.route("/api/ai/followup-recommendations", methods=["POST"])
@login_required()
def ai_followup_recommendations():
    """AI recommendations for follow-up session based on patient history and previous sessions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_number = data.get("session_number", "")
        
        if not patient_id:
            return jsonify({"error": "Patient ID required"}), 400

        # Get comprehensive patient data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Get existing follow-ups to analyze progress
        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.DESCENDING) \
                      .stream()
        
        followup_list = [f.to_dict() for f in followups]

        # Extract key data for AI analysis
        patient = all_data['patient']
        treatment_plan = all_data.get('treatment_plan', {})
        goals = all_data.get('smart_goals', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        
        # Build follow-up history for context
        previous_sessions = []
        if followup_list:
            for i, followup in enumerate(followup_list[:5]):  # Last 5 sessions
                session_info = f"Session {followup.get('session_number', '')}: Grade '{followup.get('grade', '')}', Perception '{followup.get('belief_treatment', '')}', Plan: {followup.get('treatment_plan', '')[:100]}..."
                previous_sessions.append(session_info)

        prompt = f"""
You are assisting a physiotherapist with follow-up session planning for patient {patient_id}.

PATIENT OVERVIEW:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Upcoming Session: {session_number}

TREATMENT CONTEXT:
- Provisional Diagnosis: {diagnosis.get('structure_fault', '')} - {diagnosis.get('symptom', '')}
- Treatment Goals: {goals.get('patient_goal', '')}
- Current Treatment Plan: {treatment_plan.get('treatment_plan', '')}
- Goal Timeline: {goals.get('time_duration', '')}

PREVIOUS SESSION HISTORY:
{chr(10).join(previous_sessions) if previous_sessions else 'This is the first follow-up session'}

Based on this clinical information, provide recommendations for this follow-up session:

1. GRADE OF ACHIEVEMENT GUIDANCE:
   - Expected grade range for this session (Goal Achieved, Partially Achieved, Not Achieved)
   - Factors that might influence achievement level
   - Progress indicators to assess

2. PERCEPTION OF TREATMENT ASSESSMENT:
   - Expected patient perception (Very Effective, Effective, Moderately Effective, Not Effective)
   - Key questions to ask about treatment effectiveness
   - Signs of positive/negative treatment response

3. FEEDBACK COLLECTION:
   - Important feedback areas to explore
   - Patient-reported outcome measures to consider
   - Functional improvements to assess

4. TREATMENT PLAN MODIFICATIONS:
   - Suggested adjustments based on expected progress
   - Exercise progression recommendations
   - New interventions to consider
   - Discharge planning considerations if appropriate

5. SESSION FOCUS AREAS:
   - Priority areas for this session
   - Assessment techniques to use
   - Patient education points
   - Home program updates

Keep recommendations practical and specific to physiotherapy follow-up sessions.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Follow-up Recommendations",
            details=f"Generated AI recommendations for patient {patient_id} session {session_number}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI follow-up recommendations error: {str(e)}")
        return jsonify({"error": "AI recommendations failed"}), 500

@csrf.exempt
@app.route("/api/ai/followup-progress-analysis", methods=["POST"])
@login_required()
def ai_followup_progress_analysis():
    """AI analysis of patient progress based on all follow-up sessions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        if not patient_id:
            return jsonify({"error": "Patient ID required"}), 400

        # Get comprehensive patient data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Get ALL follow-up sessions for progress analysis
        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.ASCENDING) \
                      .stream()
        
        followup_list = [f.to_dict() for f in followups]

        if not followup_list:
            return jsonify({"response": "No follow-up sessions recorded yet. Complete some sessions first to get progress analysis."})

        # Extract treatment data
        patient = all_data['patient']
        goals = all_data.get('smart_goals', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        treatment_plan = all_data.get('treatment_plan', {})
        
        # Analyze progress trends
        grade_progression = []
        perception_progression = []
        for followup in followup_list:
            grade_progression.append(f"Session {followup.get('session_number', '')}: {followup.get('grade', '')}")
            perception_progression.append(f"Session {followup.get('session_number', '')}: {followup.get('belief_treatment', '')}")

        prompt = f"""
Analyze the physiotherapy treatment progress for patient {patient_id}.

INITIAL PRESENTATION:
- Diagnosis: {diagnosis.get('structure_fault', '')} - {diagnosis.get('symptom', '')}
- Treatment Goals: {goals.get('patient_goal', '')}
- Expected Timeline: {goals.get('time_duration', '')}
- Baseline Status: {goals.get('baseline_status', '')}

TREATMENT APPROACH:
- Treatment Plan: {treatment_plan.get('treatment_plan', '')}
- Goals Targeted: {treatment_plan.get('goal_targeted', '')}

PROGRESS DATA ({len(followup_list)} sessions completed):

Grade of Achievement Progression:
{chr(10).join(grade_progression)}

Patient Perception Progression:
{chr(10).join(perception_progression)}

Treatment Plans by Session:
{chr(10).join([f"Session {f.get('session_number', '')}: {f.get('treatment_plan', '')}" for f in followup_list])}

Patient Feedback:
{chr(10).join([f"Session {f.get('session_number', '')}: {f.get('belief_feedback', '')}" for f in followup_list if f.get('belief_feedback')])}

Based on this comprehensive progress data, provide:

1. OVERALL PROGRESS ASSESSMENT:
   - Treatment effectiveness evaluation
   - Progress trend analysis (improving/plateau/declining)
   - Comparison with expected timeline

2. GRADE ACHIEVEMENT ANALYSIS:
   - Pattern of goal achievement over time
   - Factors contributing to success/challenges
   - Expected vs actual progress

3. PATIENT PERCEPTION TRENDS:
   - Patient satisfaction with treatment
   - Changes in treatment perception over time
   - Correlation between perception and objective progress

4. TREATMENT RESPONSE ANALYSIS:
   - Most effective interventions identified
   - Areas needing treatment modification
   - Patient engagement and compliance indicators

5. FUTURE RECOMMENDATIONS:
   - Next phase treatment suggestions
   - Goal modifications if needed
   - Discharge planning timeline
   - Long-term management considerations

6. OUTCOME PREDICTION:
   - Expected final outcomes based on current progress
   - Factors that may influence future success
   - Risk factors for treatment plateau or regression

Provide specific, evidence-based analysis suitable for clinical decision-making.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Progress Analysis",
            details=f"Generated progress analysis for patient {patient_id} based on {len(followup_list)} sessions"
        )
        
        return jsonify({
            "response": ai_response,
            "session_count": len(followup_list),
            "latest_grade": followup_list[-1].get('grade', '') if followup_list else '',
            "latest_perception": followup_list[-1].get('belief_treatment', '') if followup_list else ''
        })
        
    except Exception as e:
        print(f"AI progress analysis error: {str(e)}")
        return jsonify({"error": "AI progress analysis failed"}), 500

@csrf.exempt
@app.route("/api/ai/followup-session-insights", methods=["POST"])
@login_required()
def ai_followup_session_insights():
    """AI insights for a specific follow-up session"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_number = data.get("session_number")
        grade = data.get("grade", "")
        perception = data.get("perception", "")
        feedback = data.get("feedback", "")
        treatment_plan = data.get("treatment_plan", "")
        
        if not patient_id:
            return jsonify({"error": "Patient ID required"}), 400

        # Get patient context
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        goals = all_data.get('smart_goals', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        
        # Get previous sessions for context
        previous_followups = db.collection('follow_ups') \
                              .where('patient_id', '==', patient_id) \
                              .order_by('session_date', direction=firestore.Query.DESCENDING) \
                              .stream()
        
        previous_sessions = [f.to_dict() for f in previous_followups]

        prompt = f"""
Provide clinical insights for this specific follow-up session:

PATIENT CONTEXT:
- Patient: {patient.get('age_sex', '')}
- Condition: {diagnosis.get('structure_fault', '')}
- Treatment Goals: {goals.get('patient_goal', '')}

CURRENT SESSION DATA:
- Session Number: {session_number}
- Grade of Achievement: {grade}
- Patient Perception: {perception}
- Patient Feedback: {feedback}
- Treatment Plan: {treatment_plan}

PREVIOUS PROGRESS:
{chr(10).join([f"Session {p.get('session_number', '')}: {p.get('grade', '')} - {p.get('belief_treatment', '')}" for p in previous_sessions[:3]]) if previous_sessions else 'No previous sessions'}

Based on this session data, provide:

1. SESSION INTERPRETATION:
   - Analysis of the grade of achievement
   - Significance of patient perception
   - Clinical meaning of patient feedback

2. PROGRESS INDICATORS:
   - Positive indicators from this session
   - Areas of concern to monitor
   - Comparison with previous sessions

3. TREATMENT EFFECTIVENESS:
   - Assessment of current treatment approach
   - Suggested modifications based on session outcomes
   - Patient response patterns

4. NEXT SESSION PLANNING:
   - Recommendations for next treatment session
   - Areas to focus on
   - Expected progression

5. CLINICAL DECISION POINTS:
   - Key decisions needed based on this session
   - Risk factors to address
   - Opportunities for treatment advancement

Keep analysis practical and actionable for immediate clinical use.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Session Insights",
            details=f"Generated insights for patient {patient_id} session {session_number}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI session insights error: {str(e)}")
        return jsonify({"error": "AI session insights failed"}), 500

if __name__ == '__main__':
    debug_env = os.getenv("FLASK_DEBUG", "false")
    debug_mode = str(debug_env).lower() in ("1", "true", "yes", "on")
    app.run(debug=debug_mode)
