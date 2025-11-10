package com.example;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class BankAccountTest {

    private BankAccount regularAccount;
    private BankAccount vipAccount;
    private BankAccount frozenAccount;

    // 一个简单的初始化方法，你可以参考并撰写自己的初始化方法
    @Before
    public void setUp() {
        regularAccount = new BankAccount(1000, "Regular");
        vipAccount = new BankAccount(5000, "VIP");
        frozenAccount = new BankAccount(2000, "VIP");
        frozenAccount.freezeAccount();  // 初始时冻结账户
    }

    // 一个简单的存款测试，你可以仿照它编写自己的测试
    @Test
    public void testDeposit() {
        regularAccount.deposit(500);  // 正常存款
        assertEquals(1500, regularAccount.getBalance(), 0.001);  // 输出是否正确
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDepositNegativeAmount() {
        regularAccount.deposit(-100);  // 负数存款（语句覆盖，发现 Bug 1）
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDepositZeroAmount() {
        regularAccount.deposit(0);  // 零金额存款（语句覆盖，发现 Bug 2）
    }

    @Test
    public void testDepositLargeAmount() {
        regularAccount.deposit(1000000);  // 极大存款
        assertEquals(1001000, regularAccount.getBalance(), 0.001);  // 输出是否正确
    }
}
