class Calculator {
    constructor() {
        this.current = '0';
        this.history = '';
        this.isNewCalculation = true;
        this.angleMode = 'deg'; // 'deg' for degrees, 'rad' for radians
        this.updateDisplay();
    }

    // 更新显示
    updateDisplay() {
        document.getElementById('current').textContent = this.current;
        document.getElementById('history').textContent = this.history;
    }

    // 输入数字
    inputNumber(num) {
        if (this.isNewCalculation) {
            this.current = num;
            this.isNewCalculation = false;
        } else {
            if (this.current === '0' && num !== '.') {
                this.current = num;
            } else {
                this.current += num;
            }
        }
        this.updateDisplay();
    }

    // 输入运算符
    inputOperator(operator) {
        if (this.isNewCalculation && operator !== '(' && operator !== ')') {
            this.history = this.current + ' ' + operator + ' ';
        } else {
            if (operator === '(') {
                if (this.current === '0' || this.isNewCalculation) {
                    this.current = '(';
                } else {
                    this.current += '(';
                }
            } else if (operator === ')') {
                this.current += ')';
            } else {
                this.current += ' ' + operator + ' ';
            }
        }
        this.isNewCalculation = false;
        this.updateDisplay();
    }

    // 输入函数
    inputFunction(func) {
        if (this.isNewCalculation) {
            this.current = func + '(';
        } else {
            this.current += func + '(';
        }
        this.isNewCalculation = false;
        this.updateDisplay();
    }

    // 输入常数
    inputConstant(constant) {
        if (this.isNewCalculation) {
            this.current = constant;
            this.isNewCalculation = false;
        } else {
            if (this.current === '0') {
                this.current = constant;
            } else {
                this.current += constant;
            }
        }
        this.updateDisplay();
    }

    // 清除所有
    clearAll() {
        this.current = '0';
        this.history = '';
        this.isNewCalculation = true;
        this.updateDisplay();
    }

    // 清除当前输入
    clearEntry() {
        this.current = '0';
        this.updateDisplay();
    }

    // 删除最后一个字符
    deleteLast() {
        if (this.current.length > 1) {
            this.current = this.current.slice(0, -1);
        } else {
            this.current = '0';
        }
        this.updateDisplay();
    }

    // 角度转弧度
    toRadians(degrees) {
        return degrees * Math.PI / 180;
    }

    // 弧度转角度
    toDegrees(radians) {
        return radians * 180 / Math.PI;
    }

    // 阶乘函数
    factorial(n) {
        if (n < 0) return NaN;
        if (n === 0 || n === 1) return 1;
        let result = 1;
        for (let i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }

    // 处理数学函数
    evaluateFunction(expression) {
        // 替换常数
        expression = expression.replace(/π/g, Math.PI.toString());
        expression = expression.replace(/e/g, Math.E.toString());

        // 处理三角函数
        expression = expression.replace(/sin\(([^)]+)\)/g, (match, angle) => {
            const val = this.evaluateExpression(angle);
            return Math.sin(this.angleMode === 'deg' ? this.toRadians(val) : val);
        });

        expression = expression.replace(/cos\(([^)]+)\)/g, (match, angle) => {
            const val = this.evaluateExpression(angle);
            return Math.cos(this.angleMode === 'deg' ? this.toRadians(val) : val);
        });

        expression = expression.replace(/tan\(([^)]+)\)/g, (match, angle) => {
            const val = this.evaluateExpression(angle);
            return Math.tan(this.angleMode === 'deg' ? this.toRadians(val) : val);
        });

        // 处理对数函数
        expression = expression.replace(/log\(([^)]+)\)/g, (match, num) => {
            const val = this.evaluateExpression(num);
            return Math.log10(val);
        });

        expression = expression.replace(/ln\(([^)]+)\)/g, (match, num) => {
            const val = this.evaluateExpression(num);
            return Math.log(val);
        });

        // 处理平方根
        expression = expression.replace(/sqrt\(([^)]+)\)/g, (match, num) => {
            const val = this.evaluateExpression(num);
            return Math.sqrt(val);
        });

        // 处理阶乘
        expression = expression.replace(/factorial\(([^)]+)\)/g, (match, num) => {
            const val = this.evaluateExpression(num);
            return this.factorial(val);
        });

        // 处理绝对值
        expression = expression.replace(/abs\(([^)]+)\)/g, (match, num) => {
            const val = this.evaluateExpression(num);
            return Math.abs(val);
        });

        // 处理幂运算
        expression = expression.replace(/\^/g, '**');

        return expression;
    }

    // 计算表达式
    evaluateExpression(expr) {
        try {
            // 处理函数
            expr = this.evaluateFunction(expr);
            
            // 安全的eval替代方案
            return Function('"use strict"; return (' + expr + ')')();
        } catch (error) {
            throw new Error('计算错误');
        }
    }

    // 执行计算
    calculate() {
        try {
            this.history = this.current;
            let expression = this.current;

            // 替换显示符号为JavaScript运算符
            expression = expression.replace(/×/g, '*');
            expression = expression.replace(/÷/g, '/');

            const result = this.evaluateExpression(expression);
            
            if (isNaN(result) || !isFinite(result)) {
                throw new Error('计算错误');
            }

            this.current = this.formatResult(result);
            this.isNewCalculation = true;
            this.updateDisplay();
        } catch (error) {
            this.current = '错误';
            this.isNewCalculation = true;
            this.updateDisplay();
            setTimeout(() => {
                this.clearAll();
            }, 2000);
        }
    }

    // 格式化结果
    formatResult(result) {
        // 处理非常大或非常小的数字
        if (Math.abs(result) > 1e15 || (Math.abs(result) < 1e-10 && result !== 0)) {
            return result.toExponential(6);
        }
        
        // 保留适当的小数位数
        const str = result.toString();
        if (str.includes('.')) {
            const decimalPlaces = str.split('.')[1].length;
            if (decimalPlaces > 10) {
                return parseFloat(result.toFixed(10)).toString();
            }
        }
        
        return str;
    }

    // 切换角度/弧度模式
    toggleMode() {
        this.angleMode = this.angleMode === 'deg' ? 'rad' : 'deg';
        const button = document.querySelector('.btn-mode');
        const indicator = document.getElementById('modeIndicator');
        
        if (this.angleMode === 'rad') {
            button.textContent = '切换到角度模式';
            indicator.textContent = '弧度模式';
        } else {
            button.textContent = '切换到弧度模式';
            indicator.textContent = '角度模式';
        }
    }
}

// 创建计算器实例
const calculator = new Calculator();

// 全局函数供HTML调用
function inputNumber(num) {
    calculator.inputNumber(num);
}

function inputOperator(operator) {
    calculator.inputOperator(operator);
}

function inputFunction(func) {
    calculator.inputFunction(func);
}

function inputConstant(constant) {
    calculator.inputConstant(constant);
}

function clearAll() {
    calculator.clearAll();
}

function clearEntry() {
    calculator.clearEntry();
}

function deleteLast() {
    calculator.deleteLast();
}

function calculate() {
    calculator.calculate();
}

function toggleMode() {
    calculator.toggleMode();
}

// 键盘支持
document.addEventListener('keydown', function(event) {
    const key = event.key;
    
    // 数字键
    if (/[0-9]/.test(key)) {
        inputNumber(key);
    }
    // 运算符
    else if (key === '+') {
        inputOperator('+');
    }
    else if (key === '-') {
        inputOperator('-');
    }
    else if (key === '*') {
        inputOperator('*');
    }
    else if (key === '/') {
        event.preventDefault(); // 防止浏览器搜索
        inputOperator('/');
    }
    // 小数点
    else if (key === '.') {
        inputNumber('.');
    }
    // 括号
    else if (key === '(') {
        inputOperator('(');
    }
    else if (key === ')') {
        inputOperator(')');
    }
    // 等号和回车
    else if (key === '=' || key === 'Enter') {
        event.preventDefault();
        calculate();
    }
    // 退格键
    else if (key === 'Backspace') {
        deleteLast();
    }
    // 清除键
    else if (key === 'Escape') {
        clearAll();
    }
    // Delete键
    else if (key === 'Delete') {
        clearEntry();
    }
});

// 防止右键菜单
document.addEventListener('contextmenu', function(event) {
    event.preventDefault();
});
