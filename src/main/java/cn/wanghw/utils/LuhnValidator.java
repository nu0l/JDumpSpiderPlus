package cn.wanghw.utils;

/**
 * Luhn算法验证器，用于银行卡号、信用卡号等校验
 */
public class LuhnValidator {

    /**
     * 使用Luhn算法验证银行卡号
     * @param cardNumber 银行卡号
     * @return true 如果校验通过
     */
    public static boolean isValid(String cardNumber) {
        if (cardNumber == null || cardNumber.isEmpty()) {
            return false;
        }

        // 移除空格和连字符
        cardNumber = cardNumber.replaceAll("[\\s-]", "");

        // 检查长度（银行卡号通常为16-19位）
        if (cardNumber.length() < 13 || cardNumber.length() > 19) {
            return false;
        }

        // 检查是否全是数字
        if (!cardNumber.matches("\\d+")) {
            return false;
        }

        // Luhn算法校验
        int sum = 0;
        boolean alternate = false;
        for (int i = cardNumber.length() - 1; i >= 0; i--) {
            int n = Integer.parseInt(cardNumber.substring(i, i + 1));
            if (alternate) {
                n *= 2;
                if (n > 9) {
                    n = (n % 10) + 1;
                }
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }

    /**
     * 获取银行卡类型
     * @param cardNumber 银行卡号
     * @return 银行卡类型
     */
    public static String getCardType(String cardNumber) {
        if (cardNumber == null || cardNumber.isEmpty()) {
            return "Unknown";
        }

        cardNumber = cardNumber.replaceAll("[\\s-]", "");

        // Visa
        if (cardNumber.startsWith("4")) {
            return "Visa";
        }
        // MasterCard
        if (cardNumber.matches("^5[1-5].*")) {
            return "MasterCard";
        }
        // American Express
        if (cardNumber.matches("^3[47].*")) {
            return "American Express";
        }
        // UnionPay (银联)
        if (cardNumber.startsWith("62")) {
            return "UnionPay";
        }
        // JCB
        if (cardNumber.matches("^35(?:2[89]|[3-8]).*")) {
            return "JCB";
        }
        // Discover
        if (cardNumber.matches("^6(?:011|5).*")) {
            return "Discover";
        }
        // Diners Club
        if (cardNumber.matches("^3(?:0[0-5]|[68]).*")) {
            return "Diners Club";
        }

        return "Unknown";
    }

    /**
     * 格式化银行卡号（每4位加空格）
     * @param cardNumber 银行卡号
     * @return 格式化后的银行卡号
     */
    public static String formatCardNumber(String cardNumber) {
        if (cardNumber == null || cardNumber.isEmpty()) {
            return "";
        }
        cardNumber = cardNumber.replaceAll("[\\s-]", "");
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < cardNumber.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                formatted.append(" ");
            }
            formatted.append(cardNumber.charAt(i));
        }
        return formatted.toString();
    }
}
