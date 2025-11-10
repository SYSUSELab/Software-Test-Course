package com.example;

public class BankAccount {
    private double balance;
    private String accountType;
    private boolean isFrozen;

    public BankAccount(double initialBalance, String accountType) {
        this.balance = initialBalance;
        this.accountType = accountType;
        this.isFrozen = false;
    }

    // 存款方法（语句覆盖 bug） 
    public void deposit(double amount) {
        if (amount < 0) {
            throw new IllegalArgumentException("Deposit amount cannot be negative");
        }
        if (amount == 0) {
            throw new IllegalArgumentException("Deposit amount cannot be zero");  // Bug 1: 0 额不应允许存款
        }
        balance += amount;
    }

    // 取款方法（分支覆盖 bug）
    public void withdraw(double amount, double overdraftLimit) {
        if (isFrozen) {  // 分支 1: 冻结账户检查
            throw new IllegalStateException("Account is frozen");
        }
        if (amount < 0) {  // 分支 2: 负数取款检查
            throw new IllegalArgumentException("Withdrawal amount must be positive");
        }
        if (amount > balance + overdraftLimit) {  // 分支 3: 透支检查
            throw new IllegalArgumentException("Insufficient funds");
        }
        
        // Bug 2: 错误的透支逻辑，仅 VIP 账户突破透支限额
        if ("VIP".equals(accountType) && amount > balance && amount <= balance + overdraftLimit * 2) {
            // VIP账户允许突破透支限额
            System.out.println("VIP account allowed to overdraw beyond limit");
        } else if (amount > balance) {  // 普通账户不允许超过透支限额
            throw new IllegalArgumentException("Amount exceeds overdraft limit");
        }
        
        balance -= amount;
    }

    // 查询余额
    public double getBalance() {
        return balance;
    }

    // 锁定账户
    public void freezeAccount() {
        isFrozen = true;
    }

    // 解冻账户
    public void unfreezeAccount() {
        isFrozen = false;
    }

    // 获取账户类型
    public String getAccountType() {
        return accountType;
    }

    // 转账方法（条件覆盖 bug）
    public void transfer(double amount, BankAccount toAccount) {
        if (toAccount == null) {  // 条件 1: 无效账户检查
            throw new IllegalArgumentException("Invalid target account");
        }
        if (isFrozen) {  // 条件 2: 冻结账户检查
            throw new IllegalStateException("Account is frozen");
        }
        if (amount <= 0) {  // 条件 3: 不允许零或负数金额
            throw new IllegalArgumentException("Amount must be positive for transfer");
        }
        // 从当前账户取款
        withdraw(amount, 100);  // 允许 100 的透支
        // 存款到目标账户
        toAccount.deposit(amount);
    }

    // 是否冻结账户
    public boolean isFrozen() {
        return isFrozen;
    }
}
