module enc.dec.encryp_decryp {
    requires javafx.controls;
    requires javafx.fxml;


    opens enc.dec.encryp_decryp to javafx.fxml;
    exports enc.dec.encryp_decryp;
}