from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
import pandas as pd
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from logger import log
from utils import ensure_csv, next_id, filter_df, save_invoice

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # change in production

DATA_DIR = os.path.dirname(__file__)
INVOICE_DIR = os.path.join(DATA_DIR, 'invoices')

USERS_FILE = os.path.join(DATA_DIR, 'users.csv')
CATEGORIES_FILE = os.path.join(DATA_DIR, 'categories.csv')
PRODUCTS_FILE = os.path.join(DATA_DIR, 'products.csv')
ORDERS_FILE = os.path.join(DATA_DIR, 'orders.csv')
ORDER_ITEMS_FILE = os.path.join(DATA_DIR, 'order_items.csv')

# Ensure CSVs exist
ensure_csv(USERS_FILE, ['id','email','password','role','full_name'])
ensure_csv(CATEGORIES_FILE, ['id','name','description'])
ensure_csv(PRODUCTS_FILE, ['id','name','category_id','price','available'])
ensure_csv(ORDERS_FILE, ['id','user_id','status','created_at','cancelled'])
ensure_csv(ORDER_ITEMS_FILE, ['id','order_id','product_id','qty','price','product_name'])

def get_current_user():
    uid = session.get('user_id')
    if not uid: 
        return None
    df = pd.read_csv(USERS_FILE)
    if df.empty: 
        return None
    row = df[df['id'] == uid]
    if row.empty: 
        return None
    return row.iloc[0].to_dict()

def login_required(role=None):
    def wrapper(fn):
        def inner(*args, **kwargs):
            user = get_current_user()
            if not user:
                flash('Login required', 'warning')
                return redirect(url_for('login'))
            if role and user['role'] != role:
                flash('Unauthorized', 'danger')
                return redirect(url_for('index'))
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrapper

@app.route('/')
def index():
    user = get_current_user()
    return render_template('index.html', user=user)

# --------- Auth ---------
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        full_name = request.form.get('full_name','').strip()
        role = request.form.get('role','user')
        df = pd.read_csv(USERS_FILE)
        if not df.empty and (df['email'].str.lower() == email).any():
            flash('Email already exists', 'danger'); return redirect(url_for('signup'))
        uid = next_id(df, 'id')
        new = pd.DataFrame([{'id': uid, 'email': email, 'password': generate_password_hash(password),
                             'role': role, 'full_name': full_name}])
        df = pd.concat([df, new], ignore_index=True)
        df.to_csv(USERS_FILE, index=False)
        flash('Signup successful. Please login.', 'success')
        log(f"New signup: {email}")
        return redirect(url_for('login'))
    return render_template('auth_signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        df = pd.read_csv(USERS_FILE)
        row = df[df['email'].str.lower() == email]
        if row.empty or not check_password_hash(row.iloc[0]['password'], password):
            flash('Invalid credentials', 'danger'); return redirect(url_for('login'))
        session['user_id'] = int(row.iloc[0]['id'])
        flash('Welcome back!', 'success')
        return redirect(url_for('index'))
    return render_template('auth_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

# --------- Profile ---------
@app.route('/profile', methods=['GET','POST'])
@login_required()
def profile():
    user = get_current_user()
    if request.method == 'POST':
        full_name = request.form.get('full_name','')
        df = pd.read_csv(USERS_FILE)
        df.loc[df['id']==user['id'], 'full_name'] = full_name
        df.to_csv(USERS_FILE, index=False)
        flash('Profile updated', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/change-password', methods=['POST'])
@login_required()
def change_password():
    user = get_current_user()
    old = request.form['old']
    new = request.form['new']
    df = pd.read_csv(USERS_FILE)
    row = df[df['id']==user['id']].iloc[0]
    if not check_password_hash(row['password'], old):
        flash('Old password incorrect', 'danger')
        return redirect(request.referrer or url_for('profile'))
    df.loc[df['id']==user['id'], 'password'] = generate_password_hash(new)
    df.to_csv(USERS_FILE, index=False)
    flash('Password changed', 'success')
    return redirect(request.referrer or url_for('profile'))

# --------- Admin Dashboard ---------
@app.route('/admin')
@login_required('admin')
def admin_dashboard():
    products = pd.read_csv(PRODUCTS_FILE)
    orders = pd.read_csv(ORDERS_FILE)
    categories = pd.read_csv(CATEGORIES_FILE)
    users = pd.read_csv(USERS_FILE)
    return render_template('admin/dashboard.html',
                           counts={
                               'products': 0 if products.empty else len(products),
                               'orders': 0 if orders.empty else len(orders),
                               'categories': 0 if categories.empty else len(categories),
                               'users': 0 if users.empty else len(users)
                           })

# --------- Manage Category ---------
@app.route('/admin/categories')
@login_required('admin')
def admin_categories():
    q = request.args.get('q','')
    df = pd.read_csv(CATEGORIES_FILE)
    df = filter_df(df, q, ['name','description'])
    return render_template('admin/categories.html', rows=[] if df.empty else df.to_dict(orient='records'), q=q)

@app.route('/admin/categories/add', methods=['POST'])
@login_required('admin')
def admin_categories_add():
    name = request.form['name']
    description = request.form.get('description','')
    df = pd.read_csv(CATEGORIES_FILE)
    cid = next_id(df, 'id')
    new = pd.DataFrame([{'id': cid, 'name': name, 'description': description}])
    df = pd.concat([df, new], ignore_index=True)
    df.to_csv(CATEGORIES_FILE, index=False)
    flash('Category added', 'success')
    return redirect(url_for('admin_categories'))

@app.route('/admin/categories/<int:cid>/edit', methods=['POST'])
@login_required('admin')
def admin_categories_edit(cid):
    name = request.form['name']
    description = request.form.get('description','')
    df = pd.read_csv(CATEGORIES_FILE)
    df.loc[df['id']==cid, ['name','description']] = [name, description]
    df.to_csv(CATEGORIES_FILE, index=False)
    flash('Category updated', 'success')
    return redirect(url_for('admin_categories'))

# --------- Manage Products ---------
@app.route('/admin/products')
@login_required('admin')
def admin_products():
    q = request.args.get('q','')
    df = pd.read_csv(PRODUCTS_FILE)
    cats = pd.read_csv(CATEGORIES_FILE)
    if not df.empty and not cats.empty:
        df = df.merge(cats[['id','name']].rename(columns={'name':'category_name'}),
                      left_on='category_id', right_on='id', how='left', suffixes=('','_cat'))
        df.drop(columns=['id_cat'], inplace=True, errors='ignore')
    df = filter_df(df, q, ['name','category_name'])
    return render_template('admin/products.html', rows=[] if df.empty else df.to_dict(orient='records'),
                           categories=[] if cats.empty else cats.to_dict(orient='records'), q=q)

@app.route('/admin/products/add', methods=['POST'])
@login_required('admin')
def admin_products_add():
    name = request.form['name']
    category_id = int(request.form['category_id'])
    price = float(request.form['price'])
    available = request.form.get('available') == 'on'
    df = pd.read_csv(PRODUCTS_FILE)
    pid = next_id(df, 'id')
    new = pd.DataFrame([{'id': pid, 'name': name, 'category_id': category_id, 'price': price, 'available': available}])
    df = pd.concat([df, new], ignore_index=True)
    df.to_csv(PRODUCTS_FILE, index=False)
    flash('Product added', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/products/<int:pid>/edit', methods=['POST'])
@login_required('admin')
def admin_products_edit(pid):
    name = request.form['name']
    category_id = int(request.form['category_id'])
    price = float(request.form['price'])
    available = request.form.get('available') == 'on'
    df = pd.read_csv(PRODUCTS_FILE)
    df.loc[df['id']==pid, ['name','category_id','price','available']] = [name, category_id, price, available]
    df.to_csv(PRODUCTS_FILE, index=False)
    flash('Product updated', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/products/<int:pid>/delete', methods=['POST'])
@login_required('admin')
def admin_products_delete(pid):
    df = pd.read_csv(PRODUCTS_FILE)
    df = df[df['id'] != pid]
    df.to_csv(PRODUCTS_FILE, index=False)
    flash('Product deleted', 'info')
    return redirect(url_for('admin_products'))

# --------- Manage Users (Admin) ---------
@app.route('/admin/users')
@login_required('admin')
def admin_users():
    q = request.args.get('q','')
    df = pd.read_csv(USERS_FILE)
    df = filter_df(df, q, ['email','full_name','role'])
    return render_template('admin/users.html', rows=[] if df.empty else df.to_dict(orient='records'), q=q)

@app.route('/admin/users/<int:uid>/ping', methods=['POST'])
@login_required('admin')
def admin_users_ping(uid):
    # "Ping" is a placeholder action that logs a message
    row = pd.read_csv(USERS_FILE)
    if not row[row['id']==uid].empty:
        log(f"Admin pinged user id={uid}")
        flash('User pinged (logged)', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/change-password', methods=['POST'])
@login_required('admin')
def admin_change_password():
    # same as general change password but available on admin pages
    return change_password()

# --------- Orders & Bills ---------
@app.route('/menu')
@login_required()
def menu():
    df = pd.read_csv(PRODUCTS_FILE)
    df = df[df['available'] == True] if not df.empty else df
    return render_template('user/menu.html', rows=[] if df.empty else df.to_dict(orient='records'))

@app.route('/orders/add', methods=['POST'])
@login_required()
def orders_add():
    user = get_current_user()
    pid = int(request.form['product_id'])
    qty = int(request.form.get('qty', 1))
    products = pd.read_csv(PRODUCTS_FILE)
    prod = products[products['id']==pid]
    if prod.empty:
        flash('Product not found', 'danger'); return redirect(url_for('menu'))
    price = float(prod.iloc[0]['price'])
    # create order
    orders = pd.read_csv(ORDERS_FILE)
    oid = next_id(orders, 'id')
    new_order = pd.DataFrame([{'id': oid, 'user_id': user['id'], 'status': 'NEW',
                               'created_at': datetime.now().isoformat(timespec='seconds'), 'cancelled': False}])
    orders = pd.concat([orders, new_order], ignore_index=True)
    orders.to_csv(ORDERS_FILE, index=False)
    # add item
    items = pd.read_csv(ORDER_ITEMS_FILE)
    iid = next_id(items, 'id')
    new_item = pd.DataFrame([{'id': iid, 'order_id': oid, 'product_id': pid, 'qty': qty,
                              'price': price, 'product_name': prod.iloc[0]['name']}])
    items = pd.concat([items, new_item], ignore_index=True)
    items.to_csv(ORDER_ITEMS_FILE, index=False)
    flash('Order placed', 'success')
    return redirect(url_for('my_orders'))

@app.route('/my/orders')
@login_required()
def my_orders():
    user = get_current_user()
    orders = pd.read_csv(ORDERS_FILE)
    items = pd.read_csv(ORDER_ITEMS_FILE)
    products = pd.read_csv(PRODUCTS_FILE)
    df = orders[orders['user_id']==user['id']] if not orders.empty else orders
    # aggregate totals
    if not df.empty and not items.empty:
        merged = items.merge(products[['id','name']], left_on='product_id', right_on='id', how='left', suffixes=('','_prod'))
        totals = merged.groupby('order_id').apply(lambda g: (g['qty']*g['price']).sum()).reset_index(name='total')
        df = df.merge(totals, left_on='id', right_on='order_id', how='left')
        df.drop(columns=['order_id'], inplace=True, errors='ignore')
    return render_template('user/my_orders.html', rows=[] if df.empty else df.to_dict(orient='records'))

@app.route('/admin/orders')
@login_required('admin')
def admin_orders():
    q = request.args.get('q','')
    orders = pd.read_csv(ORDERS_FILE)
    users = pd.read_csv(USERS_FILE)
    items = pd.read_csv(ORDER_ITEMS_FILE)
    df = orders
    if not df.empty and not users.empty:
        df = df.merge(users[['id','email','full_name']].rename(columns={'id':'user_id','email':'user_email','full_name':'user_name'}),
                      on='user_id', how='left')
    df = filter_df(df, q, ['status','user_email','user_name','created_at'])
    # compute totals
    if not df.empty and not items.empty:
        totals = items.groupby('order_id').apply(lambda g: (g['qty']*g['price']).sum()).reset_index(name='total')
        df = df.merge(totals, left_on='id', right_on='order_id', how='left')
        df.drop(columns=['order_id'], inplace=True, errors='ignore')
    return render_template('admin/orders.html', rows=[] if df.empty else df.to_dict(orient='records'), q=q)

@app.route('/orders/<int:oid>/cancel', methods=['POST'])
@login_required()
def orders_cancel(oid):
    user = get_current_user()
    orders = pd.read_csv(ORDERS_FILE)
    row = orders[orders['id']==oid]
    if row.empty:
        flash('Order not found', 'danger'); return redirect(request.referrer or url_for('index'))
    if user['role'] != 'admin' and int(row.iloc[0]['user_id']) != int(user['id']):
        flash('Unauthorized', 'danger'); return redirect(url_for('index'))
    orders.loc[orders['id']==oid, 'cancelled'] = True
    orders.loc[orders['id']==oid, 'status'] = 'CANCELLED'
    orders.to_csv(ORDERS_FILE, index=False)
    flash('Order cancelled', 'info')
    return redirect(request.referrer or url_for('index'))

@app.route('/orders/<int:oid>/bill')
@login_required()
def orders_bill(oid):
    # view & download bill
    orders = pd.read_csv(ORDERS_FILE)
    items = pd.read_csv(ORDER_ITEMS_FILE)
    users = pd.read_csv(USERS_FILE)
    row = orders[orders['id']==oid]
    if row.empty:
        flash('Order not found', 'danger'); return redirect(request.referrer or url_for('index'))
    order = row.iloc[0].to_dict()
    user = users[users['id']==order['user_id']].iloc[0].to_dict()
    its = items[items['order_id']==oid]
    items_list = [] if its.empty else its.to_dict(orient='records')
    path = save_invoice(order, user, items_list)
    # if ?download=1 -> download
    if request.args.get('download') == '1':
        return send_file(path, as_attachment=True, download_name=os.path.basename(path), mimetype='text/html')
    # else render as iframe
    rel = os.path.basename(path)
    return render_template('user/bill_view.html', path=rel, oid=oid)

# --------- User & Admin Dashboards ---------
@app.route('/dashboard')
@login_required()
def dashboard():
    user = get_current_user()
    if user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    # user dashboard: show quick menu & orders
    return render_template('user/dashboard.html')

# ------------- Run -------------
if __name__ == '__main__':
    app.run(debug=True)
