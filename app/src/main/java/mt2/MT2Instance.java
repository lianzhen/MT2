package mt2;

import android.content.Context;
import com.csizg.securitymt2.SafetyCardMT2;

/**
 * Created by 李安阵 on 2020/1/8
 */

public class MT2Instance {
    private SafetyCardMT2 safetyCardMT2;
    private static volatile MT2Instance instance;
    private MT2Instance (){}
    public static MT2Instance getInstance(){
        if(instance==null){
            synchronized (MT2Instance.class){
                if(instance==null){
                    instance=new MT2Instance();
                }
            }
        }
        return instance;
    }
    public SafetyCardMT2 getSafetyCardMT2(Context context){
        if(safetyCardMT2==null){
            safetyCardMT2=new SafetyCardMT2(context);
        }
        return safetyCardMT2;
    }
}
