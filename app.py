from flask import Flask, render_template, request, redirect, url_for, flash, send_file, make_response
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from MySQLdb.cursors import DictCursor
from dotenv import load_dotenv
from db import init_db, mysql

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from werkzeug.utils import secure_filename
import os

import io
import base64
import unicodedata

# Cargar variables de entorno desde .env
load_dotenv()

# Inicializar la aplicación Flask
app = Flask(__name__)
app.secret_key = 'clave_secreta'

# Inicializar DB
init_db(app)

# CONFIGURACIÓN DE SUBIDA DE IMÁGENES
UPLOAD_FOLDER = 'static/img_materiales'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Crear carpeta si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

bcrypt = Bcrypt(app)

# Modelo de usuario
class Usuario(UserMixin):
    def __init__(self, id, username, password_hash, rol, nombres, apellidos, permiso, foto_perfil=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.rol = rol
        self.nombres = nombres
        self.apellidos = apellidos
        self.permiso = permiso
        self.foto_perfil = foto_perfil   # 🔥 NUEVO

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if user:
        return Usuario(
            user['id'],
            user['username'],
            user['password_hash'],
            user['rol'],
            user['nombres'],
            user['apellidos'],
            user['permiso'],
            user.get('foto_perfil')   # ← nuevo
        )
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('username', '').strip()
        contraseña = request.form.get('password')
        rol_ingreso = request.form.get('rol_ingreso')

        # 🔹 Validación básica
        if not usuario or not contraseña:
            flash('Por favor, completa todos los campos', 'warning')
            return render_template('login.html')

        try:
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT * FROM usuarios WHERE username = %s", (usuario,))
            data = cur.fetchone()
            cur.close()

            # 🔹 Verificación de usuario
            if data and bcrypt.check_password_hash(data['password_hash'], contraseña):

                # 🔹 Validación de rol
                if data['rol'] != rol_ingreso:
                    flash('El tipo de acceso seleccionado no corresponde.', 'danger')
                    return render_template('login.html')

                # 🔹 Crear usuario sesión
                user = Usuario(
                    data['id'],
                    data['username'],
                    data['password_hash'],
                    data['rol'],
                    data['nombres'],
                    data['apellidos'],
                    data['permiso']
                )

                login_user(user)
                flash('Inicio de sesión exitoso', 'success')

                # 🔹 Redirección
                if data['rol'] == 'administrador':
                    return redirect(url_for('dashboard_admin'))
                else:
                    return redirect(url_for('dashboard_usuario'))

            else:
                flash('Usuario o contraseña incorrectos', 'danger')

        except Exception as e:
            print("💥 ERROR LOGIN:", e)
            flash('Error interno del servidor', 'danger')

    return render_template('login.html')
@app.route('/verificar_password_eliminar_usuario/<int:user_id>', methods=['POST'])
@login_required
def verificar_password_eliminar_usuario(user_id):
    data = request.get_json()
    password = data.get('password')

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT * FROM usuarios WHERE id = %s", (current_user.id,))
    user = cur.fetchone()
    cur.close()

    if user and bcrypt.check_password_hash(user['password_hash'], password):
        return {'success': True}
    else:
        return {'success': False}

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):

    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('inicio'))

    cur = mysql.connection.cursor(DictCursor)

    cur.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuario = cur.fetchone()

    if not usuario:
        cur.close()
        flash('Usuario no encontrado.', 'warning')
        return redirect(url_for('listar_usuarios'))

    if request.method == 'POST':

        nombres = request.form['nombres'].strip()
        apellidos = request.form['apellidos'].strip()
        username = request.form['username'].strip()
        rol = request.form['rol']
        estado = request.form['estado']
        permiso = request.form.get('permiso')
        admin_password = request.form['admin_password']

        if not nombres or not apellidos or not username:
            flash('Todos los campos son obligatorios.', 'warning')
            return render_template('editar_usuario.html', usuario=usuario)

        if rol == 'administrador':
            permiso = 'completo'
        elif not permiso:
            permiso = 'espectador'

        if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
            flash('La contraseña del administrador es incorrecta.', 'danger')
            return render_template('editar_usuario.html', usuario=usuario)

        cur.execute("SELECT id FROM usuarios WHERE username = %s AND id != %s", (username, id))
        existente = cur.fetchone()

        if existente:
            flash('Ese nombre de usuario ya está en uso.', 'warning')
            return render_template('editar_usuario.html', usuario=usuario)

        cur.execute("""
            UPDATE usuarios
            SET nombres = %s,
                apellidos = %s,
                username = %s,
                rol = %s,
                permiso = %s,
                estado = %s
            WHERE id = %s
        """, (nombres, apellidos, username, rol, permiso, estado, id))

        mysql.connection.commit()
        cur.close()

        flash('Usuario actualizado correctamente.', 'success')
        return redirect(url_for('listar_usuarios'))

    cur.close()
    return render_template('editar_usuario.html', usuario=usuario)

@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    if current_user.rol != 'administrador':
        flash('No tienes permiso para eliminar usuarios.', 'danger')
        return redirect(url_for('listar_usuarios'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM usuarios WHERE id = %s", (id,))
        mysql.connection.commit()
        cur.close()

        flash('Usuario eliminado correctamente.', 'success')

    except Exception as e:
        print("💥 Error al eliminar:", e)
        flash('Error al eliminar usuario.', 'danger')

    return redirect(url_for('listar_usuarios'))

@app.route('/usuarios')
@login_required
def listar_usuarios():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('inicio'))

    cur = mysql.connection.cursor(DictCursor)

    # ADMIN
    cur.execute("""
    SELECT id, nombres, apellidos, dni, username, rol, permiso, ultima_actividad, foto_perfil
    FROM usuarios
    WHERE rol = 'administrador'
    ORDER BY id DESC
""")
    administradores = cur.fetchall()

    # USUARIOS
    cur.execute("""
    SELECT id, nombres, apellidos, dni, username, rol, permiso, ultima_actividad, foto_perfil
    FROM usuarios
    WHERE rol = 'usuario'
    ORDER BY id DESC
""")
    usuarios = cur.fetchall()

    cur.close()

    # 🔥👇 AQUÍ VA TU CÓDIGO
    from datetime import datetime, timedelta

    ahora = datetime.now()

    def calcular_estado(lista):
        for u in lista:
            ultima = u.get('ultima_actividad')

            if not ultima:
                u['estado_online'] = 'offline'
                u['estado_texto'] = 'Nunca'
                continue

            if isinstance(ultima, str):
                ultima = datetime.strptime(ultima, '%Y-%m-%d %H:%M:%S')

            diff = ahora - ultima

            if diff.total_seconds() <= 300:
                u['estado_online'] = 'online'
                u['estado_texto'] = 'En línea'
            elif diff.total_seconds() <= 3600:
                mins = int(diff.total_seconds() // 60)
                u['estado_online'] = 'recent'
                u['estado_texto'] = f'Hace {mins} min'
            else:
                u['estado_online'] = 'offline'
                u['estado_texto'] = 'Desconectado'

    calcular_estado(administradores)
    calcular_estado(usuarios)
    # 🔥👆 AQUÍ TERMINA

    return render_template(
        'usuarios.html',
        administradores=administradores,
        usuarios=usuarios
    )

@app.route('/registrar_usuario', methods=['GET', 'POST'])
@login_required
def registrar_usuario():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('inicio'))

    if request.method == 'POST':

        # 🔥 FUNCION PRO
        def capitalizar_nombre(texto):
            return ' '.join(p.capitalize() for p in texto.split())

        # 🔥 DATOS LIMPIOS
        nombres = capitalizar_nombre(request.form['nombres'].strip())
        apellidos = capitalizar_nombre(request.form['apellidos'].strip())
        dni = request.form['dni'].strip()
        username = request.form['username'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        admin_password = request.form['admin_password']
        rol = request.form['rol']
        permiso = request.form['permiso']

        # validar contraseñas iguales
        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return render_template('registrar_usuario.html')

        # validar longitud contraseña
        if len(password) < 8:
            flash('La contraseña debe tener mínimo 8 caracteres.', 'warning')
            return render_template('registrar_usuario.html')

        # validar DNI
        if not dni.isdigit() or len(dni) != 8:
            flash('El DNI debe tener exactamente 8 números.', 'warning')
            return render_template('registrar_usuario.html')

        # validar contraseña del admin
        if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
            flash('La contraseña del administrador es incorrecta.', 'danger')
            return render_template('registrar_usuario.html')

        if not nombres or not apellidos or not dni or not username or not password or not rol or not permiso:
            flash('Todos los campos son obligatorios.', 'warning')
            return render_template('registrar_usuario.html')

        try:
            cur = mysql.connection.cursor(DictCursor)

            # 🔥 VALIDAR USERNAME SIN MAYÚSCULAS
            cur.execute("SELECT * FROM usuarios WHERE LOWER(username) = %s", (username,))
            existente_user = cur.fetchone()

            if existente_user:
                flash('Ese nombre de usuario ya existe.', 'warning')
                cur.close()
                return render_template('registrar_usuario.html')

            # validar dni repetido
            cur.execute("SELECT * FROM usuarios WHERE dni = %s", (dni,))
            existente_dni = cur.fetchone()

            if existente_dni:
                flash('Ese DNI ya está registrado.', 'warning')
                cur.close()
                return render_template('registrar_usuario.html')

            # 🔐 HASH PASSWORD
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

            # 🔥 FORZAR PERMISO SI ES ADMIN
            if rol == 'administrador':
                permiso = 'completo'

            cur.execute("""
                INSERT INTO usuarios (nombres, apellidos, dni, username, password_hash, rol, permiso)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (nombres, apellidos, dni, username, password_hash, rol, permiso))

            mysql.connection.commit()
            cur.close()

            flash('Usuario registrado correctamente.', 'success')
            return redirect(url_for('registrar_usuario'))

        except Exception as e:
            print("💥 Error al registrar usuario:", e)
            flash('Ocurrió un error al registrar el usuario.', 'danger')

    return render_template('registrar_usuario.html')

@app.route('/dashboard_admin')
@login_required
def dashboard_admin():
    if current_user.rol != 'administrador':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('inicio'))

    cur = mysql.connection.cursor(DictCursor)

    # TOTAL DE MATERIALES
    cur.execute("""
        SELECT COUNT(*) AS total
        FROM materiales
    """)
    total_materiales = cur.fetchone()['total']

    # TOTAL DE MATERIALES CRÍTICOS
    cur.execute("""
        SELECT COUNT(*) AS total_criticos
        FROM materiales
        WHERE stock_actual < stock_optimo * 0.5
    """)
    total_criticos = cur.fetchone()['total_criticos']

    # LISTA DE MATERIALES CRÍTICOS
    cur.execute("""
        SELECT nombre, stock_actual, stock_optimo
        FROM materiales
        WHERE stock_actual < stock_optimo * 0.5
        ORDER BY stock_actual ASC
    """)
    materiales_criticos = cur.fetchall()

    cur.close()

    return render_template(
        'dashboard_admin.html',
        total_materiales=total_materiales,
        total_criticos=total_criticos,
        materiales_criticos=materiales_criticos
    )

@app.route('/dashboard_usuario')
@login_required
def dashboard_usuario():
    return render_template('dashboard_usuario.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        rol = request.form.get('rol', 'usuario')

        if not username or not password:
            flash('Todos los campos son obligatorios', 'warning')
            return render_template('registro.html')

        try:
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
            existente = cur.fetchone()

            if existente:
                flash('Este nombre de usuario ya está registrado', 'warning')
                cur.close()
                return render_template('registro.html')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            cur.execute("""
                INSERT INTO usuarios (username, password_hash, rol)
                VALUES (%s, %s, %s)
            """, (username, hashed_password, rol))
            mysql.connection.commit()
            cur.close()

            flash('Usuario registrado exitosamente', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            print("💥 Error en registro:", e)
            flash('Ocurrió un error al registrar el usuario', 'danger')

    return render_template('registro.html')

@app.context_processor
def inject_cantidad_no_leidas():
    try:
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("""
            SELECT COUNT(*) AS total FROM materiales 
            WHERE stock_actual < stock_optimo OR stock_actual > stock_maximo
        """)
        result = cur.fetchone()
        cur.close()

        return dict(
            cantidad_no_leidas=result['total'] if result else 0,
            cantidad_alerta_pred=0
        )

    except Exception as e:
        print("ERROR CONTEXT:", e)
        return dict(
            cantidad_no_leidas=0,
            cantidad_alerta_pred=0
        )

@app.route('/')
@login_required
def inicio():
    if current_user.rol == 'administrador':
        return redirect(url_for('dashboard_admin'))
    else:
        return redirect(url_for('dashboard_usuario'))  
    
@app.route('/agregar_materiales', methods=['GET', 'POST'])
@login_required
def agregar_material():
    if current_user.rol != 'administrador':
        flash('Solo el administrador puede agregar materiales.', 'danger')
        return redirect(url_for('materiales'))

    if request.method == 'POST':
        cur = None
        foto_nombre = None

        try:
            nombre = request.form.get('nombre', '').strip()
            categoria = request.form.get('categoria', '').strip()
            admin_password = request.form.get('admin_password', '').strip()

            if not nombre or not categoria:
                flash('El nombre y la categoría son obligatorios.', 'warning')
                return render_template('agregar_material.html')

            try:
                stock_actual = int(request.form.get('stock_actual', 0))
                stock_optimo = int(request.form.get('stock_optimo', 0))
                stock_maximo = int(request.form.get('stock_maximo', 0))
            except ValueError:
                flash('Los valores de stock deben ser números enteros.', 'warning')
                return render_template('agregar_material.html')

            if stock_actual < 0 or stock_optimo <= 0 or stock_maximo <= 0:
                flash('El stock actual no puede ser negativo. El óptimo y máximo deben ser mayores a 0.', 'warning')
                return render_template('agregar_material.html')

            if stock_optimo > stock_maximo:
                flash('El stock óptimo no puede ser mayor que el stock máximo.', 'warning')
                return render_template('agregar_material.html')

            if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
                flash('La contraseña del usuario actual es incorrecta.', 'danger')
                return render_template('agregar_material.html')

            foto = request.files.get('foto_material')

            if foto and foto.filename:
                if not allowed_file(foto.filename):
                    flash('Formato de imagen no permitido. Usa PNG, JPG, JPEG o WEBP.', 'warning')
                    return render_template('agregar_material.html')

                filename = secure_filename(foto.filename)
                extension = filename.rsplit('.', 1)[1].lower()
                foto_nombre = f"material_{datetime.now().strftime('%Y%m%d%H%M%S')}.{extension}"

                ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], foto_nombre)
                foto.save(ruta_foto)

            cur = mysql.connection.cursor(DictCursor)

            cur.execute("SELECT id FROM materiales WHERE LOWER(nombre) = LOWER(%s)", (nombre,))
            if cur.fetchone():
                flash('Ya existe un material con ese nombre.', 'warning')
                return render_template('agregar_material.html')

            cur.execute("""
                INSERT INTO materiales
                (nombre, categoria, stock_actual, stock_optimo, stock_maximo, foto, usuario_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                nombre,
                categoria,
                stock_actual,
                stock_optimo,
                stock_maximo,
                foto_nombre,
                current_user.id
            ))

            material_id = cur.lastrowid

            cur.execute("""
                INSERT INTO historial_movimientos
                (material_id, tipo_movimiento, cantidad, fecha_hora, usuario_id)
                VALUES (%s, 'entrada', %s, NOW(), %s)
            """, (material_id, stock_actual, current_user.id))

            mysql.connection.commit()

            if foto_nombre:
                flash('Material agregado correctamente con imagen guardada.', 'success')
            else:
                flash('Material agregado correctamente sin imagen.', 'warning')

            return redirect(url_for('materiales'))

        except Exception as e:
            mysql.connection.rollback()

            if foto_nombre:
                ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], foto_nombre)
                if os.path.exists(ruta_foto):
                    os.remove(ruta_foto)

            print("Error al agregar material:", e)
            flash(f'Error al agregar material: {str(e)}', 'danger')
            return render_template('agregar_material.html')

        finally:
            if cur:
                cur.close()

    return render_template('agregar_material.html')

@app.route('/consultar_materiales', methods=['GET', 'POST'])
@login_required
def consultar_materiales():
    materiales = None

    if request.method == 'POST':
        criterio = request.form['criterio']
        valor = request.form['valor']

        cur = mysql.connection.cursor(DictCursor)

        if criterio == 'nombre':
            cur.execute("""
                SELECT *, CASE
                    WHEN stock_actual < stock_optimo * 0.5 THEN 'Crítico'
                    WHEN stock_actual < stock_optimo THEN 'Regular'
                    WHEN stock_actual <= stock_maximo THEN 'Óptimo'
                    ELSE 'Exceso' END AS estado
                FROM materiales 
                WHERE nombre COLLATE utf8mb4_general_ci LIKE %s
            """, ('%' + valor + '%',))
            materiales = cur.fetchall()

        elif criterio == 'estado':
            cur.execute("""
                SELECT *, CASE
                    WHEN stock_actual < stock_optimo * 0.5 THEN 'Crítico'
                    WHEN stock_actual < stock_optimo THEN 'Regular'
                    WHEN stock_actual <= stock_maximo THEN 'Óptimo'
                    ELSE 'Exceso' END AS estado
                FROM materiales
            """)
            todos = cur.fetchall()

            def normalizar(texto):
                return unicodedata.normalize('NFKD', texto).encode('ASCII', 'ignore').decode('utf-8').lower()

            valor_normalizado = normalizar(valor)
            materiales = [m for m in todos if normalizar(m['estado']) == valor_normalizado]

        elif criterio == 'categoria':
            cur.execute("""
                SELECT *, CASE
                    WHEN stock_actual < stock_optimo * 0.5 THEN 'Crítico'
                    WHEN stock_actual < stock_optimo THEN 'Regular'
                    WHEN stock_actual <= stock_maximo THEN 'Óptimo'
                    ELSE 'Exceso' END AS estado
                FROM materiales 
                WHERE categoria COLLATE utf8mb4_general_ci LIKE %s
            """, ('%' + valor + '%',))
            materiales = cur.fetchall()

        cur.close()

    cur = mysql.connection.cursor(DictCursor)

    cur.execute("SELECT DISTINCT nombre FROM materiales ORDER BY nombre")
    lista_nombres = cur.fetchall()

    cur.execute("SELECT DISTINCT categoria FROM materiales ORDER BY categoria")
    lista_categorias = cur.fetchall()

    cur.close()

    return render_template(
        'consultar.html',
        materiales=materiales,
        lista_nombres=lista_nombres,
        lista_categorias=lista_categorias
    )

@app.route('/materiales')
@login_required
def materiales():
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""SELECT *, CASE
        WHEN stock_actual < stock_optimo * 0.5 THEN 'Crítico'
        WHEN stock_actual < stock_optimo THEN 'Regular'
        WHEN stock_actual <= stock_maximo THEN 'Óptimo'
        ELSE 'Exceso' END AS estado
        FROM materiales
    """)
    materiales = cur.fetchall()
    cur.close()
    return render_template('tabla_material.html', materiales=materiales)

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar(id):
    cur = mysql.connection.cursor(DictCursor)

    cur.execute("SELECT * FROM materiales WHERE id = %s", (id,))
    material = cur.fetchone()

    if not material:
        cur.close()
        flash('Material no encontrado.', 'danger')
        return redirect(url_for('materiales'))

    if request.method == 'POST':
        try:
            nombre = request.form.get('nombre', '').strip()
            categoria = request.form.get('categoria', '').strip()
            stock_actual = int(request.form.get('stock_actual', 0))
            stock_optimo = int(request.form.get('stock_optimo', 0))
            stock_maximo = int(request.form.get('stock_maximo', 0))
            admin_password = request.form.get('admin_password', '').strip()

            if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
                flash('Contraseña incorrecta. No se guardaron los cambios.', 'danger')
                cur.close()
                return render_template('editar_material.html', material=material)

            if stock_optimo > stock_maximo:
                flash('El stock óptimo no puede ser mayor que el stock máximo.', 'warning')
                cur.close()
                return render_template('editar_material.html', material=material)

            foto = request.files.get('foto_material')
            foto_nombre = material.get('foto')  # mantiene la imagen actual

            if foto and foto.filename != '':
                if allowed_file(foto.filename):
                    filename = secure_filename(foto.filename)
                    extension = filename.rsplit('.', 1)[1].lower()
                    foto_nombre = f"material_{id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{extension}"

                    foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_nombre))

                    flash('Material actualizado correctamente con nueva imagen guardada.', 'success')
                else:
                    flash('Formato de imagen no permitido. Usa PNG, JPG, JPEG o WEBP.', 'danger')
                    cur.close()
                    return render_template('editar_material.html', material=material)
            else:
                flash('Material actualizado correctamente sin cambiar imagen.', 'success')

            cur.execute("""
                UPDATE materiales
                SET nombre=%s,
                    categoria=%s,
                    stock_actual=%s,
                    stock_optimo=%s,
                    stock_maximo=%s,
                    foto=%s
                WHERE id=%s
            """, (
                nombre,
                categoria,
                stock_actual,
                stock_optimo,
                stock_maximo,
                foto_nombre,
                id
            ))

            mysql.connection.commit()
            cur.close()

            return redirect(url_for('materiales'))

        except Exception as e:
            mysql.connection.rollback()
            cur.close()
            print("Error al editar material:", e)
            flash(f'Error al editar material: {str(e)}', 'danger')
            return redirect(url_for('editar', id=id))

    cur.close()
    return render_template('editar_material.html', material=material)

@app.route('/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar(id):

    if current_user.rol != 'administrador':
        flash('Solo el administrador puede eliminar.', 'danger')
        return redirect(url_for('materiales'))

    admin_password = request.form.get('admin_password', '')

    if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
        flash('La contraseña del usuario actual es incorrecta.', 'danger')
        return redirect(url_for('materiales'))

    cur = None

    try:
        cur = mysql.connection.cursor(DictCursor)

        cur.execute("SELECT stock_actual FROM materiales WHERE id = %s", (id,))
        material = cur.fetchone()

        if not material:
            flash('Material no encontrado.', 'warning')
            return redirect(url_for('materiales'))

        stock_actual = int(material['stock_actual'])

        cur.execute("""
            INSERT INTO historial_movimientos (material_id, tipo_movimiento, cantidad, fecha_hora, usuario_id)
            VALUES (%s, 'eliminacion', %s, NOW(), %s)
        """, (id, stock_actual, current_user.id))

        cur.execute("DELETE FROM materiales WHERE id = %s", (id,))
        mysql.connection.commit()

        flash('Material eliminado correctamente.', 'success')

    except Exception as e:
        if cur:
            mysql.connection.rollback()
        flash(f'Error al eliminar el material: {str(e)}', 'danger')

    finally:
        if cur:
            cur.close()

    return redirect(url_for('materiales'))

@app.route('/notificaciones')
@login_required
def notificaciones():
    cur = mysql.connection.cursor(DictCursor)

    cur.execute("""
        SELECT 
            m.id, m.nombre, m.categoria, m.stock_actual, m.stock_optimo, m.stock_maximo,
            CASE
                WHEN m.stock_actual < m.stock_optimo * 0.5 THEN 'Crítico'
                WHEN m.stock_actual < m.stock_optimo THEN 'Regular'
                WHEN m.stock_actual <= m.stock_maximo THEN 'Óptimo'
                ELSE 'Exceso'
            END AS estado,
            (
                SELECT CONVERT_TZ(h.fecha_hora, '+00:00', '-05:00')
                FROM historial_movimientos h
                WHERE h.material_id = m.id
                ORDER BY h.fecha_hora DESC
                LIMIT 1
            ) AS ultima_fecha
        FROM materiales m
        WHERE m.stock_actual < m.stock_optimo OR m.stock_actual > m.stock_maximo
        ORDER BY 
            CASE
                WHEN m.stock_actual < m.stock_optimo * 0.5 THEN 1
                WHEN m.stock_actual < m.stock_optimo THEN 2
                ELSE 3
            END,
            m.stock_actual ASC
    """)

    materiales = cur.fetchall()
    cur.close()

    return render_template('notificaciones.html', materiales=materiales)

@app.route('/prediccion')
@login_required
def prediccion():
    resultados = []
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT * FROM materiales")
    materiales = cur.fetchall()

    for material in materiales:
        cur.execute("""
            SELECT cantidad
            FROM historial_movimientos
            WHERE material_id = %s AND tipo_movimiento = 'salida'
            ORDER BY fecha_hora ASC
            LIMIT 10
        """, (material['id'],))

        ventas = cur.fetchall()
        prediccion_valor = None

        if len(ventas) >= 2:
            unidades = [float(v['cantidad']) for v in ventas]
            prediccion_valor = sum(unidades) / len(unidades)

        resultados.append({
            'material': material,
            'prediccion': prediccion_valor,
            'grafico': None
        })

    cur.close()
    return render_template('prediccion.html', resultados=resultados, grafico_general=None)

@app.route('/historial')
@login_required
def historial():
    tipo    = request.args.get('tipo', '').strip()
    desde   = request.args.get('desde', '').strip()
    hasta   = request.args.get('hasta', '').strip()
    usuario = request.args.get('usuario', '').strip()

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SET time_zone = '-05:00'")

    # ✅ Query base sin % literales en el string principal
    query = """
        SELECT 
            h.id,
            CASE
                WHEN LOWER(h.tipo_movimiento) = 'entrada' THEN 'entrada'
                WHEN LOWER(h.tipo_movimiento) = 'salida'  THEN 'salida'
                ELSE 'eliminacion'
            END AS tipo_movimiento,
            h.cantidad,
            CONVERT_TZ(h.fecha_hora, '+00:00', '-05:00') AS fecha_hora,
            COALESCE(p.nombre, 'Material eliminado') AS nombre_material,
            u.username AS usuario,
            u.foto_perfil
        FROM historial_movimientos h
        LEFT JOIN materiales p ON h.material_id = p.id
        LEFT JOIN usuarios u ON h.usuario_id = u.id
        WHERE 1 = 1
    """

    valores = []

    if tipo:
        if tipo == 'eliminacion':
            query += " AND LOWER(h.tipo_movimiento) LIKE %s"
            valores.append('%elimin%')
        else:
            query += " AND LOWER(h.tipo_movimiento) = %s"
            valores.append(tipo)

    if desde:
        query += " AND h.fecha_hora >= %s"
        valores.append(desde + " 00:00:00")

    if hasta:
        query += " AND h.fecha_hora <= %s"
        valores.append(hasta + " 23:59:59")

    if usuario:
        query += " AND u.username LIKE %s"
        valores.append('%' + usuario + '%')

    query += " ORDER BY h.fecha_hora DESC"

    cur.execute(query, valores if valores else None)
    movimientos = cur.fetchall()
    cur.close()
    # Agregar esto antes del return render_template
    cur2 = mysql.connection.cursor(DictCursor)
    cur2.execute("""
        SELECT DISTINCT u.username 
        FROM historial_movimientos h
        JOIN usuarios u ON h.usuario_id = u.id
        ORDER BY u.username ASC
    """)
    usuarios_lista = cur2.fetchall()
    cur2.close()

    return render_template('historial.html', movimientos=movimientos, usuarios_lista=usuarios_lista)



# Al inicio donde defines UPLOAD_FOLDER, agrega:
PERFILES_FOLDER = 'static/img_perfiles'
os.makedirs(PERFILES_FOLDER, exist_ok=True)

# Nueva ruta para subir foto de perfil:
@app.route('/subir_foto_perfil', methods=['POST'])
@login_required
def subir_foto_perfil():
    foto = request.files.get('foto_perfil')

    if not foto or foto.filename == '':
        flash('No se seleccionó ninguna imagen.', 'warning')
        return redirect(url_for('mi_perfil'))

    if not allowed_file(foto.filename):
        flash('Formato no permitido. Usa PNG, JPG o WEBP.', 'danger')
        return redirect(url_for('mi_perfil'))

    extension  = foto.filename.rsplit('.', 1)[1].lower()
    foto_nombre = f"perfil_{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{extension}"
    foto.save(os.path.join(PERFILES_FOLDER, foto_nombre))

    cur = mysql.connection.cursor()
    cur.execute("UPDATE usuarios SET foto_perfil = %s WHERE id = %s",
                (foto_nombre, current_user.id))
    mysql.connection.commit()
    cur.close()

    flash('Foto de perfil actualizada correctamente.', 'success')
    return redirect(url_for('mi_perfil'))

@app.route('/salida/<int:id>', methods=['GET', 'POST'])
@login_required
def registrar_salida(id):

    if current_user.rol != 'administrador' and current_user.permiso != 'editor':
        flash('No tienes permiso para registrar salidas.', 'danger')
        return redirect(url_for('materiales'))

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT * FROM materiales WHERE id = %s", (id,))
    material = cur.fetchone()

    if not material:
        flash("Material no encontrado", "danger")
        return redirect(url_for('materiales'))

    if request.method == 'POST':
        cantidad = int(request.form['cantidad'])

        # ✅ VALIDAR CONTRASEÑA
        admin_password = request.form.get('admin_password', '').strip()
        if not admin_password:
            flash('Debes ingresar tu contraseña para confirmar.', 'danger')
            cur.close()
            return redirect(request.url)

        if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
            flash('Contraseña incorrecta. La salida no fue registrada.', 'danger')
            cur.close()
            return redirect(request.url)
        # ✅ FIN VALIDACIÓN

        if cantidad <= 0:
            flash("La cantidad debe ser mayor a 0", "warning")
            return redirect(request.url)

        if cantidad > material['stock_actual']:
            flash("No hay suficiente stock disponible", "danger")
            return redirect(request.url)

        nuevo_stock = material['stock_actual'] - cantidad
        cur.execute("UPDATE materiales SET stock_actual = %s WHERE id = %s", (nuevo_stock, id))
        cur.execute("""
            INSERT INTO historial_movimientos (material_id, tipo_movimiento, cantidad, fecha_hora, usuario_id)
            VALUES (%s, 'salida', %s, NOW(), %s)
        """, (id, cantidad, current_user.id))

        mysql.connection.commit()
        cur.close()

        flash("Salida registrada y stock actualizado", "success")
        return redirect(url_for('materiales'))

    cur.close()
    return render_template('salida_material.html', material=material)



@app.route('/mi_perfil')
@login_required
def mi_perfil():
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT * FROM usuarios WHERE id = %s", (current_user.id,))
    usuario = cur.fetchone()
    cur.close()
    return render_template('mi_perfil.html', usuario=usuario)


@app.route('/cambiar_contrasena', methods=['GET', 'POST'])
@login_required
def cambiar_contrasena():
    if request.method == 'POST':
        password_actual    = request.form.get('password_actual', '').strip()
        password_nueva     = request.form.get('password_nueva', '').strip()
        password_confirmar = request.form.get('password_confirmar', '').strip()

        if not bcrypt.check_password_hash(current_user.password_hash, password_actual):
            flash('La contraseña actual es incorrecta.', 'danger')
            return redirect(url_for('cambiar_contrasena'))

        if len(password_nueva) < 8:
            flash('La nueva contraseña debe tener mínimo 8 caracteres.', 'warning')
            return redirect(url_for('cambiar_contrasena'))

        if password_nueva != password_confirmar:
            flash('Las contraseñas nuevas no coinciden.', 'danger')
            return redirect(url_for('cambiar_contrasena'))

        if password_actual == password_nueva:
            flash('La nueva contraseña debe ser diferente a la actual.', 'warning')
            return redirect(url_for('cambiar_contrasena'))

        nuevo_hash = bcrypt.generate_password_hash(password_nueva).decode('utf-8')
        cur = mysql.connection.cursor()
        cur.execute("UPDATE usuarios SET password_hash = %s WHERE id = %s",
                    (nuevo_hash, current_user.id))
        mysql.connection.commit()
        cur.close()

        flash('Contraseña actualizada correctamente.', 'success')
        return redirect(url_for('mi_perfil'))

    return render_template('cambiar_contrasena.html')

@app.route('/entrada/<int:id>', methods=['GET', 'POST'])
@login_required
def registrar_entrada(id):

    if current_user.rol != 'administrador' and current_user.permiso != 'editor':
        flash('No tienes permiso para registrar entradas.', 'danger')
        return redirect(url_for('materiales'))

    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT * FROM materiales WHERE id = %s", (id,))
    material = cur.fetchone()

    if not material:
        flash("Material no encontrado", "danger")
        return redirect(url_for('materiales'))

    if request.method == 'POST':
        cantidad = int(request.form['cantidad'])

        # ✅ VALIDAR CONTRASEÑA
        admin_password = request.form.get('admin_password', '').strip()
        if not admin_password:
            flash('Debes ingresar tu contraseña para confirmar.', 'danger')
            cur.close()
            return redirect(request.url)

        if not bcrypt.check_password_hash(current_user.password_hash, admin_password):
            flash('Contraseña incorrecta. La entrada no fue registrada.', 'danger')
            cur.close()
            return redirect(request.url)
        # ✅ FIN VALIDACIÓN

        if cantidad <= 0:
            flash("La cantidad debe ser mayor a 0", "warning")
            return redirect(request.url)

        nuevo_stock = material['stock_actual'] + cantidad

        if nuevo_stock > material['stock_maximo']:
            flash(f"No se puede ingresar esa cantidad. El stock máximo es {material['stock_maximo']}.", "danger")
            return redirect(request.url)

        cur.execute("UPDATE materiales SET stock_actual = %s WHERE id = %s", (nuevo_stock, id))
        cur.execute("""
            INSERT INTO historial_movimientos (material_id, tipo_movimiento, cantidad, fecha_hora, usuario_id)
            VALUES (%s, 'entrada', %s, NOW(), %s)
        """, (id, cantidad, current_user.id))

        mysql.connection.commit()
        cur.close()

        flash("Entrada registrada y stock actualizado correctamente", "success")
        return redirect(url_for('materiales'))

    cur.close()
    return render_template('entrada_material.html', material=material)



@app.route('/materiales_sin_movimiento')
@login_required
def materiales_sin_movimiento():
    dias = int(request.args.get('dias', 30))
    fecha_limite = datetime.now() - timedelta(days=dias)

    cur = mysql.connection.cursor(DictCursor)

    cur.execute("""
        SELECT 
            p.id, 
            p.nombre, 
            p.categoria,
            p.stock_actual,
            p.stock_optimo,
            p.stock_maximo,
            MAX(h.fecha_hora) AS ultima_salida
        FROM materiales p
        LEFT JOIN historial_movimientos h 
            ON p.id = h.material_id 
            AND h.tipo_movimiento = 'salida'
        GROUP BY 
            p.id, 
            p.nombre, 
            p.categoria,
            p.stock_actual,
            p.stock_optimo,
            p.stock_maximo
        HAVING 
            ultima_salida IS NULL 
            OR ultima_salida < %s
        ORDER BY ultima_salida ASC
    """, (fecha_limite,))

    materiales = cur.fetchall()
    cur.close()

    return render_template(
        'materiales_sin_movimiento.html',
        materiales=materiales,
        dias=dias
    )

@app.route('/clasificacion_abc')
@login_required
def clasificacion_abc():
    cur = mysql.connection.cursor(DictCursor)

    # Obtener los materiales con salidas y valor consumido
    cur.execute("""
        SELECT p.id, p.nombre, p.categoria, SUM(h.cantidad) AS total_salidas, 
               p.precio_unitario, SUM(h.cantidad * p.precio_unitario) AS valor_consumido
        FROM historial_movimientos h
        JOIN materiales p ON h.material_id = p.id
        WHERE h.tipo_movimiento = 'salida'
        GROUP BY p.id
        ORDER BY valor_consumido DESC
    """)
    materiales = cur.fetchall()

    total_valor = sum(p['valor_consumido'] or 0 for p in materiales)

    acumulado = 0
    abc_counts = {'A': 0, 'B': 0, 'C': 0}  # Contadores para el gráfico

    for p in materiales:
        valor = p['valor_consumido'] or 0
        porcentaje = (valor / total_valor) * 100 if total_valor > 0 else 0
        acumulado += porcentaje

        if acumulado <= 80:
            p['clasificacion'] = 'A'
            abc_counts['A'] += 1
        elif acumulado <= 95:
            p['clasificacion'] = 'B'
            abc_counts['B'] += 1
        else:
            p['clasificacion'] = 'C'
            abc_counts['C'] += 1

    cur.close()
    return render_template('clasificacion_abc.html', materiales=materiales, abc_counts=abc_counts)

@app.route('/sugerencias_pedido')
@login_required
def sugerencias_pedido():
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("""
        SELECT id, nombre, categoria, stock_actual, stock_optimo, stock_maximo
        FROM materiales
        WHERE stock_actual < stock_optimo
    """)
    materiales = cur.fetchall()

    for p in materiales:
        p['cantidad_sugerida'] = p['stock_optimo'] - p['stock_actual']

    cur.close()
    return render_template('sugerencias_pedido.html', materiales=materiales)

@app.route('/reportes')
@login_required
def reportes():
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM materiales")
    total = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM materiales WHERE stock_actual < stock_optimo * 0.5")
    criticos = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM materiales WHERE stock_actual >= stock_optimo * 0.5 AND stock_actual < stock_optimo")
    regulares = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) AS total FROM materiales WHERE stock_actual >= stock_optimo AND stock_actual <= stock_maximo")
    optimos = cur.fetchone()['total']

    return render_template('reportes.html',
                           total_materiales=total,
                           total_criticos=criticos,
                           total_regulares=regulares,
                           total_optimos=optimos)



@app.route('/exportar_materiales_pdf')
@login_required
def exportar_materiales_pdf():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from flask import make_response
        import io

        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)

        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT * FROM materiales")
        materiales = cur.fetchall()
        cur.close()

        y = 750

        pdf.setFont("Helvetica", 10)

        pdf.drawString(50, y, "LISTA DE MATERIALES")
        y -= 20

        for m in materiales:
            texto = f"{m['id']} - {m['nombre']} - Stock: {m['stock_actual']}"
            pdf.drawString(50, y, texto)
            y -= 15

            if y < 50:
                pdf.showPage()
                y = 750

        pdf.save()

        buffer.seek(0)

        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=materiales.pdf'

        return response

    except Exception as e:
        print("💥 ERROR PDF:", e)
        return "Error al generar PDF"
    
if __name__ == '__main__':
     app.run(debug=True, port=5001)