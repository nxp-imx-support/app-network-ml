# 导入必要的模块  
from flask import Flask, render_template, request, redirect  
  
# 创建Flask应用实例  
app = Flask(__name__)  
  
# 定义路由和处理函数  
@app.route('/')  
def home():  
    return render_template('home.html')  
  
@app.route('/about')  
def about():  
    return render_template('about.html')  
  
@app.route('/contact', methods=['GET', 'POST'])  
def contact():  
    if request.method == 'POST':  
        name = request.form['name']  
        email = request.form['email']  
        message = request.form['message']  
        # 在这里可以处理提交的数据，例如发送邮件等操作  
        return redirect('/success')  
    return render_template('contact.html')  
  
@app.route('/success')  
def success():  
    return render_template('success.html')  
  
# 运行Flask应用  
if __name__ == '__main__':  
    app.run(debug=True)